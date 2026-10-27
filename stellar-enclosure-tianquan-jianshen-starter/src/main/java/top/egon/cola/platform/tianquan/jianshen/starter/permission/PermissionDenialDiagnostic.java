package top.egon.cola.platform.tianquan.jianshen.starter.permission;

import top.egon.cola.platform.tianquan.jianshen.contract.authorization.RuntimePolicyBinding;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.CatalogScope;
import java.time.Instant;
import java.util.List;
import java.util.Map;

/** In-process decision evidence; no credential, submitted value, or business object is included. */
public record PermissionDenialDiagnostic(
        String decisionId, String traceId, String reasonCode, String resourceKey,
        String userId, CatalogScope scope, String catalogVersion, String authVersion, String policyVersion,
        List<String> rootRoleIds, List<String> effectiveRoleIds,
        Map<String, Object> requirement, List<PermissionFact> permissionFacts, List<String> missingResourceScopes,
        RuntimePolicyBinding binding, Instant snapshotAt, Instant occurredAt,
        String decisionKind, Map<String, Object> details, boolean resolvePermissionSources
) {
    public PermissionDenialDiagnostic(String decisionId, String traceId, String reasonCode, String resourceKey,
            String userId, CatalogScope scope, String catalogVersion, String authVersion, String policyVersion,
            List<String> rootRoleIds, List<String> effectiveRoleIds, Map<String, Object> requirement,
            List<PermissionFact> permissionFacts, List<String> missingResourceScopes,
            RuntimePolicyBinding binding, Instant snapshotAt, Instant occurredAt) {
        this(decisionId, traceId, reasonCode, resourceKey, userId, scope, catalogVersion, authVersion, policyVersion,
                rootRoleIds, effectiveRoleIds, requirement, permissionFacts, missingResourceScopes, binding,
                snapshotAt, occurredAt, "API", Map.of(), true);
    }

    public PermissionDenialDiagnostic {
        rootRoleIds = List.copyOf(rootRoleIds);
        effectiveRoleIds = List.copyOf(effectiveRoleIds);
        requirement = Map.copyOf(requirement);
        permissionFacts = List.copyOf(permissionFacts);
        missingResourceScopes = List.copyOf(missingResourceScopes);
        decisionKind = java.util.Objects.requireNonNull(decisionKind, "decisionKind");
        details = Map.copyOf(details);
    }

    public record PermissionFact(String code, boolean granted, boolean scopeQualified,
                                 boolean scopeMappingConfigured, List<String> missingScopes) {
        public PermissionFact { missingScopes = List.copyOf(missingScopes); }
    }
}
