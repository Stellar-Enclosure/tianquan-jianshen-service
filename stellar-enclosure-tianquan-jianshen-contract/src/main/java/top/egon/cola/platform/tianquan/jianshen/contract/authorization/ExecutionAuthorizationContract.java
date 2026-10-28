package top.egon.cola.platform.tianquan.jianshen.contract.authorization;

import java.time.Instant;

/** Internal request and attested decision for one deferred execution intent. */
public final class ExecutionAuthorizationContract {
    public static final String PATH = "/internal/v1/authorization/execution-grants:decide";
    public static final String SERVICE_SCOPE = "service:authorization:execution";
    public static final int MAX_REQUEST_BYTES = 64 * 1024;

    private ExecutionAuthorizationContract() { }

    public record Request(String systemCode, String grantId, String ciphertext) {
        public Request {
            if (systemCode == null || !systemCode.matches("[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}")
                    || grantId == null || !grantId.matches("9[0-9]{62}") || ciphertext == null
                    || !ciphertext.startsWith("ENC:v1:") || ciphertext.length() > 32_768) {
                throw new IllegalArgumentException("EXECUTION_AUTHORIZATION_REQUEST_INVALID");
            }
        }
        @Override public String toString() { return "ExecutionAuthorizationRequest[redacted]"; }
    }

    public record Decision(String grantId, String issuer, String tenantId, String subject, String resource, String purpose,
                           String intentId, String bindingSha256, boolean sessionRequired, Instant deadlineAt, Instant expiresAt,
                           long authVersion, long policyVersion) {
        public Decision {
            if (grantId == null || !grantId.matches("9[0-9]{62}") || issuer == null || issuer.isBlank()
                    || tenantId == null || !tenantId.matches("[1-9][0-9]{0,18}") || subject == null || subject.isBlank()
                    || resource == null || resource.isBlank() || purpose == null || !purpose.matches("[A-Z][A-Z0-9_]{0,95}") || intentId == null
                    || bindingSha256 == null || !bindingSha256.matches("[0-9a-f]{64}") || deadlineAt == null || expiresAt == null
                    || expiresAt.isAfter(deadlineAt) || authVersion < 0 || policyVersion < 0) {
                throw new IllegalArgumentException("EXECUTION_AUTHORIZATION_DECISION_INVALID");
            }
            try {
                if (intentId.length() != 36 || !java.util.UUID.fromString(intentId).toString().equals(intentId)) {
                    throw new IllegalArgumentException();
                }
                Long.parseLong(tenantId);
            } catch (IllegalArgumentException invalid) { throw new IllegalArgumentException("EXECUTION_AUTHORIZATION_DECISION_INVALID"); }
        }
        @Override public String toString() { return "ExecutionAuthorizationDecision[redacted]"; }
    }
}
