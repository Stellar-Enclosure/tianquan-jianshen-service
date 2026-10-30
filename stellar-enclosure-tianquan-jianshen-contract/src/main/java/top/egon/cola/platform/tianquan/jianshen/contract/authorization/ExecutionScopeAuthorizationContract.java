package top.egon.cola.platform.tianquan.jianshen.contract.authorization;

import java.time.Instant;
import java.util.Map;
import java.util.Objects;

/** Optional current data-scope projection for a separately authorized deferred intent; the original decision protocol is unchanged. */
public final class ExecutionScopeAuthorizationContract {
    public static final String PATH = "/internal/v1/authorization/execution-grants:decide-scopes";
    public static final String SERVICE_SCOPE = "service:authorization:execution-scopes";
    private ExecutionScopeAuthorizationContract() { }

    public record Decision(ExecutionAuthorizationContract.Decision execution, String rbac3UserId, Instant generatedAt, Map<String, DataScopeDecision> dataScopes) {
        public Decision {
            execution = Objects.requireNonNull(execution, "execution"); generatedAt = Objects.requireNonNull(generatedAt, "generatedAt");
            if (rbac3UserId == null || !rbac3UserId.matches("[1-9][0-9]{0,18}") || !generatedAt.isBefore(execution.expiresAt())) throw invalid();
            try { Long.parseLong(rbac3UserId); } catch (NumberFormatException invalid) { throw invalid(); }
            dataScopes = Map.copyOf(Objects.requireNonNull(dataScopes, "dataScopes")); if (dataScopes.size() > 64) throw invalid();
            for (var item : dataScopes.entrySet()) {
                var scope = item.getValue();
                if (!item.getKey().equals(scope.permissionCode()) || !execution.tenantId().equals(scope.tenantId()) || !rbac3UserId.equals(scope.subjectId())
                        || execution.authVersion() != scope.authVersion() || execution.policyVersion() != scope.policyVersion() || !generatedAt.equals(scope.decidedAt())) throw invalid();
            }
        }
        @Override public String toString() { return "ExecutionScopeDecision[redacted]"; }
    }
    private static IllegalArgumentException invalid() { return new IllegalArgumentException("EXECUTION_SCOPE_DECISION_INVALID"); }
}
