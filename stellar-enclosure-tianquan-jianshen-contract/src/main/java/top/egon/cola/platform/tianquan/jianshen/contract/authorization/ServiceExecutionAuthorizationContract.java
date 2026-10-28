package top.egon.cola.platform.tianquan.jianshen.contract.authorization;

import com.fasterxml.jackson.annotation.JsonFormat;
import java.net.URI;
import java.time.Instant;
import java.util.UUID;

/** Internal policy decision for a separately attested SERVICE execution intent. */
public final class ServiceExecutionAuthorizationContract {
    public static final String PATH = "/internal/v1/authorization/service-execution-grants:decide";
    public static final String SERVICE_SCOPE = "service:authorization:service-execution";
    public static final int MAX_REQUEST_BYTES = 64 * 1024;

    private ServiceExecutionAuthorizationContract() { }

    public record Request(String systemCode, String grantId, String ciphertext) {
        public Request {
            if (systemCode == null || !systemCode.matches("[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}")
                    || grantId == null || !grantId.matches("8[0-9]{62}") || ciphertext == null
                    || !ciphertext.startsWith("ENC:v1:") || ciphertext.length() > 32_768) throw invalid();
        }
        @Override public String toString() { return "ServiceExecutionAuthorizationRequest[redacted]"; }
    }

    public record Subject(String clientId, String appId, String businessCode, String applicationCode,
                          String environment, String resourceUri) {
        public Subject {
            if (!text(clientId) || !text(appId) || !text(businessCode) || !text(applicationCode) || !text(environment)) throw invalid();
            secureUri(resourceUri);
        }
        @Override public String toString() { return "ServiceExecutionAuthorizationSubject[redacted]"; }
    }

    public record Decision(String grantId, String issuer, String tenantId, String subject, Subject subjectSource,
            String resource, String purpose, String intentId, String bindingSha256, boolean sessionRequired,
            @JsonFormat(shape = JsonFormat.Shape.STRING) Instant deadlineAt,
            @JsonFormat(shape = JsonFormat.Shape.STRING) Instant expiresAt, long catalogVersion, long policyVersion) {
        public Decision {
            if (grantId == null || !grantId.matches("8[0-9]{62}") || tenantId == null || !tenantId.matches("[1-9][0-9]{0,18}")
                    || !text(subject) || subjectSource == null || !subject.equals(subjectSource.clientId())
                    || purpose == null || !purpose.matches("[A-Z][A-Z0-9_]{0,95}") || bindingSha256 == null
                    || !bindingSha256.matches("[0-9a-f]{64}") || deadlineAt == null || expiresAt == null
                    || expiresAt.isAfter(deadlineAt) || catalogVersion <= 0 || policyVersion < 0) throw invalid();
            secureUri(issuer); secureUri(resource);
            try {
                Long.parseLong(tenantId);
                if (intentId == null || intentId.length() != 36 || !UUID.fromString(intentId).toString().equals(intentId)) throw invalid();
            } catch (IllegalArgumentException malformed) { throw invalid(); }
        }
        @Override public String toString() { return "ServiceExecutionAuthorizationDecision[redacted]"; }
    }

    private static boolean text(String value) {
        return value != null && !value.isBlank() && value.length() <= 128 && value.equals(value.trim())
                && value.chars().noneMatch(Character::isISOControl);
    }

    private static void secureUri(String value) {
        try {
            URI uri = URI.create(value);
            if (!"https".equalsIgnoreCase(uri.getScheme()) || uri.getHost() == null || uri.getUserInfo() != null
                    || uri.getQuery() != null || uri.getFragment() != null || !uri.normalize().equals(uri)
                    || value.length() > 2048) throw invalid();
        } catch (RuntimeException malformed) { throw invalid(); }
    }

    private static IllegalArgumentException invalid() { return new IllegalArgumentException("SERVICE_EXECUTION_AUTHORIZATION_INVALID"); }
}
