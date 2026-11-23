package top.egon.cola.platform.tianquan.jianshen.admin.authorization.grant.rolepermission;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import top.egon.cola.platform.tianquan.jianshen.admin.audit.service.AuditQueryService;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.grant.rolepermission.domain.dto.ReplaceRolePermissionsRequestDTO;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.grant.rolepermission.repository.RolePermissionGrantRepository;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.grant.rolepermission.service.RolePermissionGrantService;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.grant.rolepermission.domain.vo.RolePermissionGrantViewVO;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.runtime.repository.AuthorizationEventPublisher;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.runtime.state.repository.TenantAuthorizationStateRepository;
import top.egon.cola.platform.tianquan.jianshen.admin.registration.catalog.repository.PermissionCatalogScopeRepository;
import top.egon.cola.platform.tianquan.jianshen.admin.registration.catalog.repository.CatalogAdministrationGuard;
import top.egon.cola.platform.tianquan.jianshen.admin.registration.catalog.domain.convertor.PermissionCatalogJson;
import top.egon.cola.platform.tianquan.jianshen.admin.shared.domain.DatabaseClock;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.CatalogScope;
import top.egon.cola.platform.tianquan.jianshen.core.rule.Rbac3RuleViolation;
import top.egon.cola.platform.tianquan.jianshen.starter.security.Rbac3UserDetails;

import java.time.Instant;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

class RolePermissionGrantTest {
    private static final Instant NOW = Instant.parse("2026-10-25T00:00:00Z");
    private static final CatalogScope SCOPE = new CatalogScope("1", "10", "biz", "app", "default", "test");
    private final CatalogAdministrationGuard guard = mock(CatalogAdministrationGuard.class);
    private final RolePermissionGrantRepository grants = mock(RolePermissionGrantRepository.class);
    private final TenantAuthorizationStateRepository policy = mock(TenantAuthorizationStateRepository.class);
    private final AuthorizationEventPublisher events = mock(AuthorizationEventPublisher.class);
    private final AuditQueryService audit = mock(AuditQueryService.class);
    private final DatabaseClock clock = mock(DatabaseClock.class);
    private final Rbac3UserDetails actor = mock(Rbac3UserDetails.class);
    private final RolePermissionGrantService service = new RolePermissionGrantService(guard, grants, policy, events, audit, clock);
    private final PermissionCatalogScopeRepository.ScopeState scope = new PermissionCatalogScopeRepository.ScopeState(SCOPE, 20, 1, 0);
    private final ReplaceRolePermissionsRequestDTO request = new ReplaceRolePermissionsRequestDTO(SCOPE, List.of("app.read"), "0", null, null);

    @BeforeEach
    void prepare() {
        when(clock.transactionNow()).thenReturn(NOW);
        when(actor.rbac3UserId()).thenReturn("90");
        when(guard.require(SCOPE, actor, RolePermissionGrantService.MANAGE, NOW)).thenReturn(scope);
        when(grants.replace(scope, 40, request, "90", NOW)).thenReturn(new RolePermissionGrantRepository.Mutation("1", 1, 0));
        when(policy.increment(10L, "90")).thenReturn(1L);
    }

    @Test
    void readUsesTheReadGuardAndRepeatableReadWithoutChangingTransactionRouting() throws Exception {
        var view = new RolePermissionGrantViewVO(SCOPE, "40", "0", "1", List.of());
        when(guard.requireRead(SCOPE, actor, RolePermissionGrantService.READ, NOW)).thenReturn(scope);
        when(grants.read(scope, 40)).thenReturn(view);

        assertEquals(view, service.read(SCOPE, "40", actor));

        verify(guard).requireRead(SCOPE, actor, RolePermissionGrantService.READ, NOW);
        verify(guard, never()).require(any(), any(), anyString(), any());
        verifyNoInteractions(policy, events, audit);
        var transaction = RolePermissionGrantService.class.getMethod("read", CatalogScope.class, String.class, Rbac3UserDetails.class)
                .getAnnotation(org.springframework.transaction.annotation.Transactional.class);
        assertNotNull(transaction);
        assertFalse(transaction.readOnly());
        assertEquals(org.springframework.transaction.annotation.Isolation.REPEATABLE_READ, transaction.isolation());
    }

    @Test
    void explicitUserGrantSharesPolicyAuditAndOutboxTransaction() {
        var result = service.replace("40", request, actor);
        assertEquals(List.of("app.read"), result.permissionCodes());
        assertEquals("1", result.version());
        assertEquals("1", result.policyVersion());
        var order = inOrder(guard, grants, policy, events, audit);
        order.verify(guard).require(SCOPE, actor, RolePermissionGrantService.MANAGE, NOW);
        order.verify(grants).replace(scope, 40, request, "90", NOW);
        order.verify(policy).increment(10L, "90");
        order.verify(events).enqueue(argThat(event -> event.eventType().equals("ROLE_PERMISSION_CHANGED")
                && event.safePayload().get("catalogScopeId").equals("1") && event.safePayload().get("permissionVersion").equals("1")));
        order.verify(audit).record(any());
    }

    @Test
    void versionAndScopeFailureCannotPublishAnyPermissionMutation() {
        when(grants.replace(scope, 40, request, "90", NOW)).thenThrow(new Rbac3RuleViolation("RESOURCE_VERSION_CONFLICT"));
        assertThrows(Rbac3RuleViolation.class, () -> service.replace("40", request, actor));
        verifyNoInteractions(policy, events, audit);
    }

    @Test
    void fullReplacementAcceptsEmptySetButRejectsDuplicateCodesAndOldResourceIds() {
        assertEquals(List.of(), new ReplaceRolePermissionsRequestDTO(SCOPE, List.of(), "0", null, null).permissionCodes());
        assertThrows(IllegalArgumentException.class, () -> new ReplaceRolePermissionsRequestDTO(SCOPE, List.of("app.read", "app.read"), "0", null, null));
        var json = new PermissionCatalogJson(new ObjectMapper().registerModule(new JavaTimeModule()));
        assertThrows(IllegalArgumentException.class, () -> json.read("{\"target\":" + json.write(SCOPE)
                + ",\"resourceIds\":[\"101\"],\"expectedVersion\":\"0\"}", ReplaceRolePermissionsRequestDTO.class));
        assertThrows(IllegalArgumentException.class, () -> json.read("{\"target\":" + json.write(SCOPE)
                + ",\"permissionCodes\":[\"app.read\"],\"expectedVersion\":0}", ReplaceRolePermissionsRequestDTO.class));
    }
    @Test
    void outboxFailureIsNotReportedAsASuccessfulGrant() {
        doThrow(new IllegalStateException("outbox unavailable")).when(events).enqueue(any());
        assertThrows(IllegalStateException.class, () -> service.replace("40", request, actor));
        verifyNoInteractions(audit);
    }

    @Test
    void auditFailureEscapesTheOwningWritableTransaction() throws Exception {
        doThrow(new IllegalStateException("audit unavailable")).when(audit).record(any());
        assertThrows(IllegalStateException.class, () -> service.replace("40", request, actor));
        var transaction = RolePermissionGrantService.class.getMethod("replace", String.class,
                ReplaceRolePermissionsRequestDTO.class, Rbac3UserDetails.class)
                .getAnnotation(org.springframework.transaction.annotation.Transactional.class);
        assertNotNull(transaction);
        assertFalse(transaction.readOnly());
        assertEquals(org.springframework.transaction.annotation.Propagation.REQUIRED, transaction.propagation());
    }

}
