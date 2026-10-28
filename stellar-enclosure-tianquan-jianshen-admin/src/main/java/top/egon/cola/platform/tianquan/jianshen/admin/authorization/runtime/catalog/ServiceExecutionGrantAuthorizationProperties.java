package top.egon.cola.platform.tianquan.jianshen.admin.authorization.runtime.catalog;

import org.springframework.boot.context.properties.ConfigurationProperties;
import top.egon.cola.platform.tianquan.shoubing.contract.execution.ServiceExecutionGrantContract;

import java.net.URI;
import java.util.List;
import java.util.Set;

/** Fixed SERVICE subjects and current catalog resources permitted for deferred execution. */
@ConfigurationProperties("egon.tianquan-jianshen.service-execution-grants")
public record ServiceExecutionGrantAuthorizationProperties(boolean enabled, List<Policy> policies) {
    public ServiceExecutionGrantAuthorizationProperties {
        policies = policies == null ? List.of() : List.copyOf(policies);
        if (policies.size() > 256 || enabled && policies.isEmpty()
                || policies.stream().map(Policy::identity).distinct().count() != policies.size()) {
            throw new IllegalArgumentException("SERVICE_EXECUTION_AUTHORIZATION_POLICIES_INVALID");
        }
    }

    public record Policy(String issuer, String tenantId, String systemCode, String purpose, String resourceKey,
            String resourcePath, String sessionResourceKey, String sessionResourcePath, Set<String> requiredScopes,
            Set<String> sessionScopes, List<Subject> subjects) {
        public Policy {
            secureUri(issuer);
            if (tenantId == null || !tenantId.matches("[1-9][0-9]{0,18}") || !identifier(systemCode, 128)
                    || purpose == null || !purpose.matches("[A-Z][A-Z0-9_]{0,95}") || !identifier(resourceKey, 200)
                    || !path(resourcePath) || (sessionResourceKey == null) != (sessionResourcePath == null)
                    || sessionResourceKey != null && (!identifier(sessionResourceKey, 200) || !path(sessionResourcePath))) {
                throw new IllegalArgumentException("SERVICE_EXECUTION_AUTHORIZATION_POLICY_INVALID");
            }
            try { Long.parseLong(tenantId); }
            catch (NumberFormatException invalid) { throw new IllegalArgumentException("SERVICE_EXECUTION_AUTHORIZATION_POLICY_INVALID"); }
            requiredScopes = scopes(requiredScopes, false);
            sessionScopes = scopes(sessionScopes, true);
            subjects = subjects == null ? List.of() : List.copyOf(subjects);
            if (subjects.isEmpty() || subjects.size() > 128 || subjects.stream().distinct().count() != subjects.size()
                    || sessionResourceKey == null && !sessionScopes.isEmpty() || sessionResourceKey != null && sessionScopes.isEmpty()) {
                throw new IllegalArgumentException("SERVICE_EXECUTION_AUTHORIZATION_POLICY_INVALID");
            }
        }

        private String identity() { return issuer + "|" + tenantId + "|" + systemCode + "|" + purpose; }
    }

    public record Subject(String clientId, String appId, String businessCode, String applicationCode,
                          String environment, String resourceUri) {
        public Subject {
            if (!text(clientId) || !text(appId) || !text(businessCode) || !text(applicationCode) || !text(environment)) {
                throw new IllegalArgumentException("SERVICE_EXECUTION_AUTHORIZATION_SUBJECT_INVALID");
            }
            secureUri(resourceUri);
        }

        boolean matches(ServiceExecutionGrantContract.Source source) {
            return source != null && clientId.equals(source.clientId()) && appId.equals(source.appId())
                    && businessCode.equals(source.businessCode()) && applicationCode.equals(source.applicationCode())
                    && environment.equals(source.environment()) && resourceUri.equals(source.resourceUri());
        }

        @Override public String toString() { return "ServiceExecutionAuthorizationSubject[redacted]"; }
    }

    private static Set<String> scopes(Set<String> values, boolean allowEmpty) {
        values = values == null ? Set.of() : Set.copyOf(values);
        if ((!allowEmpty && values.isEmpty()) || values.size() > 64
                || values.stream().anyMatch(value -> !value.matches("[A-Za-z0-9:._-]{1,128}"))) {
            throw new IllegalArgumentException("SERVICE_EXECUTION_AUTHORIZATION_SCOPES_INVALID");
        }
        return values;
    }

    private static boolean text(String value) {
        return value != null && !value.isBlank() && value.length() <= 128 && value.equals(value.trim())
                && value.chars().noneMatch(Character::isISOControl);
    }

    private static boolean identifier(String value, int maximum) {
        return value != null && value.length() <= maximum && value.matches("[A-Za-z0-9][A-Za-z0-9._:/-]*");
    }

    private static boolean path(String value) {
        if (value == null || !value.matches("/[A-Za-z0-9._~/-]{1,512}") || value.contains("//")) return false;
        return URI.create(value).normalize().toString().equals(value);
    }

    private static void secureUri(String value) {
        try {
            URI uri = URI.create(value);
            if (!"https".equalsIgnoreCase(uri.getScheme()) || uri.getHost() == null || uri.getUserInfo() != null
                    || uri.getQuery() != null || uri.getFragment() != null || !uri.normalize().equals(uri)
                    || value.length() > 2048) throw new IllegalArgumentException();
        } catch (RuntimeException invalid) { throw new IllegalArgumentException("SERVICE_EXECUTION_AUTHORIZATION_URI_INVALID"); }
    }
}
