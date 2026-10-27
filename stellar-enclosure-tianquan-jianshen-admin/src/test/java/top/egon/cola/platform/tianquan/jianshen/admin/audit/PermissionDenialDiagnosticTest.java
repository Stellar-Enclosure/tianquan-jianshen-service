package top.egon.cola.platform.tianquan.jianshen.admin.audit;

import jakarta.persistence.EntityManager;
import jakarta.persistence.Query;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.SimpleTransactionStatus;
import org.springframework.transaction.support.TransactionSynchronization;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import top.egon.cola.platform.tianquan.jianshen.admin.audit.controller.AuditController;
import top.egon.cola.platform.tianquan.jianshen.admin.audit.domain.dto.AuditCommandDTO;
import top.egon.cola.platform.tianquan.jianshen.admin.audit.domain.dto.QueryDTO;
import top.egon.cola.platform.tianquan.jianshen.admin.audit.domain.vo.AuditQueryPageVO;
import top.egon.cola.platform.tianquan.jianshen.admin.audit.repository.DecisionPermissionSourceRepository;
import top.egon.cola.platform.tianquan.jianshen.admin.audit.repository.AuditRepository;
import top.egon.cola.platform.tianquan.jianshen.admin.audit.domain.vo.AuditVO;
import top.egon.cola.platform.tianquan.jianshen.admin.audit.service.AuditQueryService;
import top.egon.cola.platform.tianquan.jianshen.admin.audit.service.PermissionDenialDiagnosticRecorder;
import top.egon.cola.platform.tianquan.jianshen.contract.authorization.RuntimePolicyBinding;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.CatalogScope;
import top.egon.cola.platform.tianquan.jianshen.starter.permission.PermissionDenialDiagnostic;
import top.egon.cola.platform.tianquan.jianshen.starter.security.Rbac3UserDetails;
import top.egon.cola.platform.tianquan.jianshen.admin.shared.tenant.domain.TenantContext;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.annotation.RequiresPermissions;

import java.time.Instant;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

class PermissionDenialDiagnosticTest {
    private static final Instant NOW = Instant.parse("2026-10-25T00:00:00Z");
    private static final PermissionDenialDiagnostic EVENT = new PermissionDenialDiagnostic(
            "decision-1", "trace-1", "OAUTH_SCOPE_DENIED", "shop.api.read", "30",
            new CatalogScope("10", "20", "commerce", "shop", "default", "test"), "1", "2", "3",
            List.of("40"), List.of("50"), Map.of("mode", "ALL"),
            List.of(new PermissionDenialDiagnostic.PermissionFact("order:read", true, false, true, List.of("read:scope")),
                    new PermissionDenialDiagnostic.PermissionFact("order:write", false, false, true, List.of())),
            List.of("api:read"), new RuntimePolicyBinding("shop-java", "1", "a".repeat(64), "b".repeat(64), "c".repeat(64)), NOW, NOW);

    @Test void resolvesOnlyTheRequiredGrantedPermissionsAtTheOriginalSnapshotTime() {
        var em = mock(EntityManager.class);
        var scope = query(em, "from rbac3_catalog_scope", List.of(10L));
        var policy = query(em, "from rbac3_tenant_authorization_state", List.of(3L));
        var user = query(em, "from rbac3_user", List.of(2L));
        var activation = query(em, "from rbac3_catalog_active_pointer", List.of(1L));
        var grants = query(em, "from rbac3_catalog_role_permission", java.util.Collections.singletonList(new Object[]{50L, "order:read"}));
        var result = new DecisionPermissionSourceRepository(em).resolve(EVENT);
        assertThat(result.status()).isEqualTo("VERIFIED");
        assertThat(result.rolesByPermission()).containsExactlyEntriesOf(Map.of("order:read", List.of("50")));
        verify(scope).setParameter("tenant", 20L);
        verify(policy).setParameter("tenant", 20L);
        verify(user).setParameter("tenant", 20L);
        verify(user).setParameter("user", 30L);
        verify(activation).setParameter("scope", 10L);
        verify(grants).setParameter("roles", List.of(50L));
        verify(grants).setParameter("codes", java.util.Set.of("order:read"));
        verify(grants).setParameter("at", NOW);
        verify(em, times(3)).createNativeQuery(contains("for share nowait"));
    }

    @Test void versionChangesOrMissingSourceNeverUseCurrentGrantsAsHistoricalEvidence() {
        var em = mock(EntityManager.class);
        query(em, "from rbac3_catalog_scope", List.of(10L));
        query(em, "from rbac3_tenant_authorization_state", List.of(4L));
        var changed = new DecisionPermissionSourceRepository(em).resolve(EVENT);
        assertThat(changed.status()).isEqualTo("POLICY_VERSION_CHANGED");
        assertThat(changed.rolesByPermission()).isEmpty();
        verify(em, never()).createNativeQuery(contains("from rbac3_catalog_role_permission"));

        var second = mock(EntityManager.class);
        query(second, "from rbac3_catalog_scope", List.of(10L));
        query(second, "from rbac3_tenant_authorization_state", List.of(3L));
        query(second, "from rbac3_user", List.of(2L));
        query(second, "from rbac3_catalog_active_pointer", List.of(1L));
        query(second, "from rbac3_catalog_role_permission", List.of());
        var incomplete = new DecisionPermissionSourceRepository(second).resolve(EVENT);
        assertThat(incomplete.status()).isEqualTo("INCOMPLETE");
        assertThat(incomplete.rolesByPermission()).isEmpty();

        var accountChanged = mock(EntityManager.class);
        query(accountChanged, "from rbac3_catalog_scope", List.of(10L));
        query(accountChanged, "from rbac3_tenant_authorization_state", List.of(3L));
        query(accountChanged, "from rbac3_user", List.of(7L));
        assertThat(new DecisionPermissionSourceRepository(accountChanged).resolve(EVENT).status()).isEqualTo("AUTH_VERSION_CHANGED");

        var catalogChanged = mock(EntityManager.class);
        query(catalogChanged, "from rbac3_catalog_scope", List.of(10L));
        query(catalogChanged, "from rbac3_tenant_authorization_state", List.of(3L));
        query(catalogChanged, "from rbac3_user", List.of(2L));
        query(catalogChanged, "from rbac3_catalog_active_pointer", List.of(8L));
        assertThat(new DecisionPermissionSourceRepository(catalogChanged).resolve(EVENT).status()).isEqualTo("CATALOG_VERSION_CHANGED");
    }

    @Test void dataScopeRulesAreReadAtTheOriginalVersionWithoutExposingReferenceIds() {
        var event = new PermissionDenialDiagnostic(EVENT.decisionId(), EVENT.traceId(), "DATA_SCOPE_MISSING", EVENT.resourceKey(),
                EVENT.userId(), EVENT.scope(), EVENT.catalogVersion(), EVENT.authVersion(), EVENT.policyVersion(),
                EVENT.rootRoleIds(), EVENT.effectiveRoleIds(), EVENT.requirement(), EVENT.permissionFacts(), List.of(),
                EVENT.binding(), NOW, NOW, "DATA_SCOPE_POLICY", Map.of("finalObjectDecision", false), true);
        var em = mock(EntityManager.class);
        query(em, "from rbac3_catalog_scope", List.of(10L));
        query(em, "from rbac3_tenant_authorization_state", List.of(3L));
        query(em, "from rbac3_user", List.of(2L));
        query(em, "from rbac3_catalog_active_pointer", List.of(1L));
        query(em, "from rbac3_catalog_role_permission", java.util.Collections.singletonList(new Object[]{50L, "order:read"}));
        var data = query(em, "from rbac3_data_rule d", java.util.Collections.singletonList(new Object[]{70L, 50L, "DEPT", 0L, 9L}));
        var result = new DecisionPermissionSourceRepository(em).resolve(event);
        assertThat(result.status()).isEqualTo("VERIFIED");
        assertThat(result.dataScopeRules()).containsExactly(Map.of("ruleId", "70", "roleId", "50", "scopeType", "DEPT",
                "referenceCount", 0L, "directoryVersion", "9"));
        verify(data).setParameter("roles", List.of(50L));
        verify(data).setParameter("codes", java.util.Set.of("order:read"));
        verify(data).setParameter("at", NOW);
        assertThat(result.dataScopeRules().toString()).doesNotContain("ref_id");
        var changed = mock(EntityManager.class);
        query(changed, "from rbac3_catalog_scope", List.of(10L));
        query(changed, "from rbac3_tenant_authorization_state", List.of(4L));
        var stale = new DecisionPermissionSourceRepository(changed).resolve(event);
        assertThat(stale.status()).isEqualTo("POLICY_VERSION_CHANGED");
        assertThat(stale.dataScopeRules()).isEmpty();
        verify(changed, never()).createNativeQuery(contains("from rbac3_data_rule d"));
    }

    @Test void recordsTenantScopedEvidenceAndReportsSourceFailuresWithoutChangingDenial() {
        var sources = mock(DecisionPermissionSourceRepository.class);
        var audit = mock(AuditQueryService.class);
        var manager = mock(PlatformTransactionManager.class);
        when(manager.getTransaction(any())).thenReturn(new SimpleTransactionStatus());
        when(sources.resolve(EVENT)).thenReturn(new DecisionPermissionSourceRepository.Sources("VERIFIED", Map.of("order:read", List.of("50"))));
        var recorder = new PermissionDenialDiagnosticRecorder(sources, audit, manager);
        recorder.record(EVENT);
        var command = ArgumentCaptor.forClass(AuditCommandDTO.class);
        verify(audit).record(command.capture());
        var written = command.getValue();
        assertThat(written.tenantId()).isEqualTo("20");
        assertThat(written.requestId()).isEqualTo("decision-1");
        assertThat(written.reasonCode()).isEqualTo("OAUTH_SCOPE_DENIED");
        assertThat(written.outcome()).isEqualTo("DENIED");
        assertThat(written.afterSnapshot().get("permissionSourceStatus")).isEqualTo("VERIFIED");
        assertThat(written.afterSnapshot().get("rolesByPermission")).isEqualTo(Map.of("order:read", List.of("50")));
        assertThat(written.afterSnapshot().toString()).doesNotContain("bearer", "token", "credential");
        verify(manager).commit(any());

        reset(audit);
        when(sources.resolve(EVENT)).thenThrow(new IllegalStateException("unavailable"));
        recorder.record(EVENT);
        verify(audit).record(command.capture());
        assertThat(command.getValue().afterSnapshot().get("permissionSourceStatus")).isEqualTo("UNAVAILABLE");
        assertThat(command.getValue().afterSnapshot().get("rolesByPermission")).isEqualTo(Map.of());
        reset(audit);
        when(audit.record(any())).thenThrow(new IllegalStateException("unavailable"));
        assertDoesNotThrow(() -> recorder.record(EVENT));
    }

    @Test void waitsForTheOriginalTransactionToFinishBeforeRecording() {
        var sources = mock(DecisionPermissionSourceRepository.class);
        var audit = mock(AuditQueryService.class);
        var manager = mock(PlatformTransactionManager.class);
        when(manager.getTransaction(any())).thenReturn(new SimpleTransactionStatus());
        when(sources.resolve(EVENT)).thenReturn(new DecisionPermissionSourceRepository.Sources("VERIFIED", Map.of()));
        var recorder = new PermissionDenialDiagnosticRecorder(sources, audit, manager);
        TransactionSynchronizationManager.setActualTransactionActive(true);
        TransactionSynchronizationManager.initSynchronization();
        try {
            recorder.record(EVENT);
            verifyNoInteractions(sources, audit, manager);
            var callbacks = TransactionSynchronizationManager.getSynchronizations();
            TransactionSynchronizationManager.setActualTransactionActive(false);
            callbacks.forEach(callback -> callback.afterCompletion(TransactionSynchronization.STATUS_ROLLED_BACK));
            verify(sources).resolve(EVENT);
            verify(audit).record(any());
            var definition = ArgumentCaptor.forClass(org.springframework.transaction.TransactionDefinition.class);
            verify(manager).getTransaction(definition.capture());
            assertThat(definition.getValue().getPropagationBehavior()).isEqualTo(org.springframework.transaction.TransactionDefinition.PROPAGATION_REQUIRES_NEW);
        } finally {
            TransactionSynchronizationManager.clearSynchronization();
            TransactionSynchronizationManager.setActualTransactionActive(false);
        }
    }

    @Test void realAuditSanitizerPreservesDiagnosticVersionsAndRoles() {
        var sources = mock(DecisionPermissionSourceRepository.class);
        when(sources.resolve(EVENT)).thenReturn(new DecisionPermissionSourceRepository.Sources("VERIFIED", Map.of("order:read", List.of("50"))));
        var store = mock(AuditRepository.class);
        when(store.append(any())).thenAnswer(invocation -> invocation.getArgument(0));
        var manager = mock(PlatformTransactionManager.class);
        when(manager.getTransaction(any())).thenReturn(new SimpleTransactionStatus());
        var audit = new AuditQueryService(store, java.time.Clock.fixed(NOW, java.time.ZoneOffset.UTC));
        new PermissionDenialDiagnosticRecorder(sources, audit, manager).record(EVENT);
        var saved = ArgumentCaptor.forClass(AuditVO.class);
        verify(store).append(saved.capture());
        assertThat(saved.getValue().afterSnapshot()).containsEntry("authVersion", "2")
                .containsEntry("policyVersion", "3")
                .containsEntry("rolesByPermission", Map.of("order:read", List.of("50")));
        assertThat(saved.getValue().payloadChecksum()).startsWith("sha256:");
    }

    @Test void bindingMismatchPersistsNoRoleSourcesFromTheRejectedSnapshot() {
        var event = new PermissionDenialDiagnostic(EVENT.decisionId(), EVENT.traceId(), "AUTH_DEPLOYMENT_BINDING_MISMATCH",
                EVENT.resourceKey(), EVENT.userId(), EVENT.scope(), EVENT.catalogVersion(), EVENT.authVersion(), EVENT.policyVersion(),
                List.of(), List.of(), Map.of(), List.of(), List.of(), EVENT.binding(), NOW, NOW,
                "DEPLOYMENT_BINDING", Map.of("failedChecks", List.of("ARTIFACT_DIGEST_MISMATCH")), false);
        var sources = mock(DecisionPermissionSourceRepository.class);
        var audit = mock(AuditQueryService.class);
        var manager = mock(PlatformTransactionManager.class);
        when(manager.getTransaction(any())).thenReturn(new SimpleTransactionStatus());
        new PermissionDenialDiagnosticRecorder(sources, audit, manager).record(event);
        verifyNoInteractions(sources);
        var saved = ArgumentCaptor.forClass(AuditCommandDTO.class);
        verify(audit).record(saved.capture());
        assertThat(saved.getValue().afterSnapshot().get("decisionKind")).isEqualTo("DEPLOYMENT_BINDING");
        assertThat(saved.getValue().afterSnapshot().get("permissionSourceStatus")).isEqualTo("NOT_EVALUATED");
        assertThat(saved.getValue().afterSnapshot().get("rolesByPermission")).isEqualTo(Map.of());
    }

    @Test void diagnosticQueryUsesTheAuthenticatedTenantAndExistingAuditPermission() {
        var service = mock(AuditQueryService.class);
        when(service.query(any(), anyString(), anyString(), anyString())).thenReturn(new AuditQueryPageVO(List.of(), null));
        var principal = mock(Rbac3UserDetails.class);
        when(principal.rbac3UserId()).thenReturn("30");
        SecurityContextHolder.getContext().setAuthentication(new UsernamePasswordAuthenticationToken(principal, null, List.of()));
        TenantContext.set(new TenantContext("20", "20", false));
        try {
            new AuditController(service).auditLogs(NOW.minusSeconds(60), NOW, null, null, null, null, null,
                    "decision-1", null, null, 50, null, "query-1", "trace-1");
            var query = ArgumentCaptor.forClass(QueryDTO.class);
            verify(service).query(query.capture(), eq("30"), eq("query-1"), eq("trace-1"));
            assertThat(query.getValue().tenantId()).isEqualTo("20");
            assertThat(query.getValue().requestId()).isEqualTo("decision-1");
            var method = java.util.Arrays.stream(AuditController.class.getDeclaredMethods())
                    .filter(candidate -> candidate.getName().equals("auditLogs")).findFirst().orElseThrow();
            assertThat(method.getAnnotation(RequiresPermissions.class).codes()).containsExactly("system:audit:read");
        } finally {
            TenantContext.clear();
            SecurityContextHolder.clearContext();
        }
    }

    @Test void springEventListenerRecordsThePublishedDiagnostic() {
        var sources = mock(DecisionPermissionSourceRepository.class);
        var audit = mock(AuditQueryService.class);
        var manager = mock(PlatformTransactionManager.class);
        when(manager.getTransaction(any())).thenReturn(new SimpleTransactionStatus());
        when(sources.resolve(EVENT)).thenReturn(new DecisionPermissionSourceRepository.Sources("VERIFIED", Map.of()));
        try (var context = new org.springframework.context.annotation.AnnotationConfigApplicationContext()) {
            context.registerBean(DecisionPermissionSourceRepository.class, () -> sources);
            context.registerBean(AuditQueryService.class, () -> audit);
            context.registerBean(PlatformTransactionManager.class, () -> manager);
            context.register(PermissionDenialDiagnosticRecorder.class);
            context.refresh();
            context.publishEvent(EVENT);
            verify(audit).record(any());
        }
    }

    private static Query query(EntityManager em, String sqlFragment, List<?> rows) {
        var query = mock(Query.class, RETURNS_SELF);
        when(em.createNativeQuery(contains(sqlFragment))).thenReturn(query);
        doReturn(rows).when(query).getResultList();
        return query;
    }
}
