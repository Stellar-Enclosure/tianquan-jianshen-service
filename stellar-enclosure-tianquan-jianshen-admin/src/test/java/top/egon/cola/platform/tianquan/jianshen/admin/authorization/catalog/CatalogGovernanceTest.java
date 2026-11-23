package top.egon.cola.platform.tianquan.jianshen.admin.authorization.catalog;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.persistence.EntityManager;
import jakarta.persistence.Query;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.catalog.domain.dto.CatalogGovernanceCommandDTO;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.catalog.repository.CatalogGovernanceRepository;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.catalog.service.CatalogGovernanceService;
import top.egon.cola.platform.tianquan.jianshen.admin.registration.catalog.repository.CatalogAdministrationGuard;
import top.egon.cola.platform.tianquan.jianshen.admin.registration.catalog.repository.PermissionCatalogScopeRepository;
import top.egon.cola.platform.tianquan.jianshen.admin.registration.catalog.domain.convertor.PermissionCatalogJson;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.CatalogScope;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.PermissionManifest;
import top.egon.cola.platform.tianquan.jianshen.core.rule.Rbac3RuleViolation;
import top.egon.cola.platform.tianquan.jianshen.starter.security.Rbac3UserDetails;

import java.time.Instant;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;
import static top.egon.cola.platform.tianquan.jianshen.admin.registration.catalog.service.PermissionCatalogActivationService.READ;

class CatalogGovernanceTest {
    private static final CatalogScope SCOPE = new CatalogScope("1", "10", "biz", "app", "default", "test");
    private static final Instant NOW = Instant.parse("2026-10-25T00:00:00Z");
    private final EntityManager entityManager = mock(EntityManager.class);
    private final Query query = mock(Query.class, RETURNS_SELF);
    private final PermissionCatalogScopeRepository scopes = mock(PermissionCatalogScopeRepository.class);
    private final CatalogGovernanceRepository repository = new CatalogGovernanceRepository(entityManager, scopes, new PermissionCatalogJson(new ObjectMapper()));

    @BeforeEach
    void prepare() {
        when(entityManager.createNativeQuery(anyString())).thenReturn(query);
        when(query.getResultList()).thenReturn(List.of((Object) new Object[]{101L, "app.field", "api", "DISABLED", 4L, "FIELD", "", null}));
        when(query.executeUpdate()).thenReturn(1);
        when(query.getSingleResult()).thenReturn(false);
        when(scopes.lockExistingOwner(SCOPE, "api")).thenReturn(owner("api", List.of("app.")));
        when(scopes.lockOwner(SCOPE, "next-api")).thenReturn(owner("next-api", List.of("app.")));
    }

    @Test
    void explicitOwnershipTransferKeepsIdKeyAndDisabledStateAndInvalidatesBothPlans() {
        var result = repository.mutate(command(CatalogGovernanceCommandDTO.Action.TRANSFER, "4", "next-api"), "90", NOW);
        assertEquals("101", result.after().id());
        assertEquals("app.field", result.after().key());
        assertEquals("DISABLED", result.after().state());
        assertEquals("next-api", result.after().producerId());
        assertEquals("5", result.after().version());
        verify(query).setParameter("state", "DISABLED");
        verify(query).setParameter("owner", "next-api");
        verify(entityManager, times(2)).createNativeQuery(contains("update rbac3_catalog_producer set version=version+1"));
        verify(entityManager, never()).createNativeQuery(startsWith("update rbac3_catalog_role_permission"));
    }

    @Test
    void transferOutsideDestinationOwnershipAndStaleExpectedVersionAreRejected() {
        when(scopes.lockOwner(SCOPE, "next-api")).thenReturn(owner("next-api", List.of("other.")));
        assertThrows(Rbac3RuleViolation.class, () -> repository.mutate(command(CatalogGovernanceCommandDTO.Action.TRANSFER, "4", "next-api"), "90", NOW));
        assertThrows(Rbac3RuleViolation.class, () -> repository.mutate(command(CatalogGovernanceCommandDTO.Action.DISABLE, "3", null), "90", NOW));
        verify(query, never()).executeUpdate();
    }

    @Test
    void retirementRequiresReferencesToBeRemovedButDisableIsImmediate() {
        when(query.getSingleResult()).thenReturn(true);
        assertThrows(Rbac3RuleViolation.class, () -> repository.mutate(command(CatalogGovernanceCommandDTO.Action.RETIRE, "4", null), "90", NOW));
        verify(query, never()).executeUpdate();
        assertEquals("DISABLED", repository.mutate(command(CatalogGovernanceCommandDTO.Action.DISABLE, "4", null), "90", NOW).after().state());
    }

    @Test
    void retiredKeysCannotBeReenabledOrTransferred() {
        when(query.getResultList()).thenReturn(List.of((Object) new Object[]{101L, "app.field", "api", "RETIRED", 4L, "FIELD", "", null}));
        for (var action : CatalogGovernanceCommandDTO.Action.values()) {
            assertThrows(Rbac3RuleViolation.class, () -> repository.mutate(command(action, "4", action == CatalogGovernanceCommandDTO.Action.TRANSFER ? "next-api" : null), "90", NOW));
        }
        verify(query, never()).executeUpdate();
        verifyNoInteractions(scopes);
    }

    @Test
    void unsupportedRestoreAndExtraneousOwnerAreRejectedAtWireBoundary() {
        assertThrows(IllegalArgumentException.class, () -> command(CatalogGovernanceCommandDTO.Action.DISABLE, "4", "next-api"));
        var json = new PermissionCatalogJson(new ObjectMapper());
        assertThrows(IllegalArgumentException.class, () -> json.read("{\"target\":" + json.write(SCOPE)
                + ",\"kind\":\"RESOURCE\",\"identityId\":\"101\",\"action\":\"ENABLE\",\"expectedVersion\":\"4\"}", CatalogGovernanceCommandDTO.class));
    }

    @Test
    void catalogReadsCheckAuthorizationWithoutTakingTheMutationFence() {
        var actor = mock(Rbac3UserDetails.class, RETURNS_DEEP_STUBS);
        when(actor.tenantId()).thenReturn(SCOPE.tenantId());
        when(actor.snapshot().permissionSnapshot().catalogScope()).thenReturn(SCOPE);
        var guard = mock(CatalogAdministrationGuard.class);
        var reads = mock(CatalogGovernanceRepository.class);
        var service = new CatalogGovernanceService(guard, reads, null, null, null, () -> NOW);
        var kind = CatalogGovernanceCommandDTO.Kind.RESOURCE;

        service.scopes(0, 20, actor);
        service.page(SCOPE, kind, 0, 20, actor);
        service.detail(SCOPE, kind, 101, actor);

        verify(guard, times(3)).requireRead(SCOPE, actor, READ, NOW);
        verifyNoMoreInteractions(guard);
        verify(reads).scopes(SCOPE.tenantId(), 0, 20);
        verify(reads).page(SCOPE, kind, 0, 20);
        verify(reads).detail(SCOPE, kind, 101);
    }

    private CatalogGovernanceCommandDTO command(CatalogGovernanceCommandDTO.Action action, String version, String target) {
        return new CatalogGovernanceCommandDTO(SCOPE, CatalogGovernanceCommandDTO.Kind.RESOURCE, "101", action, version, target);
    }

    private PermissionCatalogScopeRepository.Owner owner(String producer, List<String> prefixes) {
        return new PermissionCatalogScopeRepository.Owner(SCOPE, 20, producer, PermissionManifest.ProducerKind.JAVA,
                prefixes, prefixes, List.of("app/"), List.of("api"), 1, 5, 1, 0);
    }
}
