package top.egon.cola.platform.tianquan.jianshen.admin.audit.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Component;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.support.TransactionTemplate;
import top.egon.cola.platform.tianquan.jianshen.admin.audit.domain.dto.AuditCommandDTO;
import top.egon.cola.platform.tianquan.jianshen.admin.audit.repository.DecisionPermissionSourceRepository;
import top.egon.cola.platform.tianquan.jianshen.starter.permission.PermissionDenialDiagnostic;
import java.util.LinkedHashMap;
import java.util.Map;

/** Stores supplementary local diagnostics in the existing tenant-scoped, append-only audit store. */
@Component
public class PermissionDenialDiagnosticRecorder {
    private static final Logger LOG = LoggerFactory.getLogger(PermissionDenialDiagnosticRecorder.class);
    private final DecisionPermissionSourceRepository sources;
    private final AuditQueryService audit;
    private final TransactionTemplate appendTransaction;

    public PermissionDenialDiagnosticRecorder(DecisionPermissionSourceRepository sources, AuditQueryService audit,
                                              PlatformTransactionManager transactionManager) {
        this.sources = sources;
        this.audit = audit;
        this.appendTransaction = new TransactionTemplate(transactionManager);
        this.appendTransaction.setPropagationBehavior(TransactionDefinition.PROPAGATION_REQUIRES_NEW);
    }

    @EventListener
    public void record(PermissionDenialDiagnostic event) {
        if (org.springframework.transaction.support.TransactionSynchronizationManager.isActualTransactionActive()) {
            if (!org.springframework.transaction.support.TransactionSynchronizationManager.isSynchronizationActive()) {
                LOG.warn("Decision diagnostic could not be scheduled decisionId={} reason=TRANSACTION_SYNCHRONIZATION_UNAVAILABLE", event.decisionId());
                return;
            }
            org.springframework.transaction.support.TransactionSynchronizationManager.registerSynchronization(
                    new org.springframework.transaction.support.TransactionSynchronization() {
                        @Override public void afterCompletion(int status) { recordSafely(event); }
                    });
            return;
        }
        recordSafely(event);
    }

    private void recordSafely(PermissionDenialDiagnostic event) {
        try { persist(event); }
        catch (RuntimeException failure) {
            LOG.warn("Decision diagnostic unavailable decisionId={} failureType={}", event.decisionId(), failure.getClass().getSimpleName());
        }
    }

    private void persist(PermissionDenialDiagnostic event) {
        DecisionPermissionSourceRepository.Sources resolved;
        try { resolved = event.resolvePermissionSources() ? sources.resolve(event)
                : new DecisionPermissionSourceRepository.Sources("NOT_EVALUATED", Map.of()); }
        catch (RuntimeException failure) {
            LOG.warn("Decision permission source unavailable decisionId={} failureType={}", event.decisionId(), failure.getClass().getSimpleName());
            resolved = new DecisionPermissionSourceRepository.Sources("UNAVAILABLE", Map.of());
        }
        var scope = event.scope();
        var binding = event.binding();
        Map<String, Object> details = new LinkedHashMap<>();
        details.put("decisionId", event.decisionId());
        details.put("decisionKind", event.decisionKind());
        details.put("decisionDetails", event.details());
        details.put("resourceKey", event.resourceKey());
        details.put("catalogScope", Map.of("catalogScopeId", scope.catalogScopeId(), "tenantId", scope.tenantId(),
                "businessCode", scope.businessCode(), "applicationCode", scope.applicationCode(),
                "namespaceCode", scope.namespaceCode(), "environment", scope.environment()));
        details.put("catalogVersion", event.catalogVersion());
        details.put("authVersion", event.authVersion());
        details.put("policyVersion", event.policyVersion());
        details.put("snapshotAt", event.snapshotAt().toString());
        details.put("rootRoleIds", event.rootRoleIds());
        details.put("effectiveRoleIds", event.effectiveRoleIds());
        details.put("requirement", event.requirement());
        details.put("missingResourceScopes", event.missingResourceScopes());
        details.put("permissionFacts", event.permissionFacts().stream().map(fact -> Map.of(
                "code", fact.code(), "granted", fact.granted(), "scopeQualified", fact.scopeQualified(),
                "scopeMappingConfigured", fact.scopeMappingConfigured(), "missingScopes", fact.missingScopes())).toList());
        details.put("permissionSourceStatus", resolved.status());
        details.put("rolesByPermission", resolved.rolesByPermission());
        if ("DATA_SCOPE_POLICY".equals(event.decisionKind())) details.put("dataScopeRules", resolved.dataScopeRules());
        details.put("producer", Map.of("producerId", binding.producerId(), "producerVersion", binding.producerVersion(),
                "artifactDigest", binding.artifactDigest(), "policyDigest", binding.policyDigest(), "manifestDigest", binding.manifestDigest()));
        var command = new AuditCommandDTO(scope.tenantId(), "AUTHORIZATION_DENIED_DIAGNOSTIC", "DENIED", "INFO", "USER",
                event.userId(), "RESOURCE", event.resourceKey().length() <= 128 ? event.resourceKey() : null, null,
                event.reasonCode(), event.decisionId(), event.traceId(), Map.of(), details, event.occurredAt());
        appendTransaction.executeWithoutResult(status -> audit.record(command));
    }
}
