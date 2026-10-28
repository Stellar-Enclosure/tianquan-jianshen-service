package top.egon.cola.platform.tianquan.jianshen.admin.authorization.runtime.catalog;

import java.net.URI;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.springframework.boot.context.properties.ConfigurationProperties;

/** Finite deployment-owned rules, selected only after the requester and owner-issued intent are verified. */
@ConfigurationProperties("egon.tianquan-jianshen.execution-grants")
public record ExecutionGrantAuthorizationProperties(boolean enabled, List<Policy> policies) {
    public ExecutionGrantAuthorizationProperties {
        policies = policies == null ? List.of() : List.copyOf(policies);
        if (policies.size() > 256 || enabled && policies.isEmpty()
                || policies.stream().map(policy -> policy.systemCode() + "|" + policy.purpose()).distinct().count() != policies.size()) {
            throw new IllegalArgumentException("EXECUTION_AUTHORIZATION_POLICIES_INVALID");
        }
    }

    public record Policy(String systemCode, String purpose, String resourceKey, String resourcePath,
                         String sessionResourceKey, String sessionResourcePath, Set<String> requiredPermissions,
                         Set<String> sessionPermissions, Map<String, Set<String>> permissionScopes) {
        public Policy {
            if (!identifier(systemCode, 128) || purpose == null || !purpose.matches("[A-Z][A-Z0-9_]{0,95}")
                    || !identifier(resourceKey, 200) || !path(resourcePath)
                    || (sessionResourceKey == null) != (sessionResourcePath == null)
                    || sessionResourceKey != null && (!identifier(sessionResourceKey, 200) || !path(sessionResourcePath))) {
                throw new IllegalArgumentException("EXECUTION_AUTHORIZATION_POLICY_INVALID");
            }
            requiredPermissions = permissions(requiredPermissions, false);
            sessionPermissions = permissions(sessionPermissions, true);
            if (sessionResourceKey == null && !sessionPermissions.isEmpty() || sessionResourceKey != null && sessionPermissions.isEmpty()
                    || permissionScopes == null || permissionScopes.isEmpty() || permissionScopes.size() > 128) {
                throw new IllegalArgumentException("EXECUTION_AUTHORIZATION_POLICY_INVALID");
            }
            Map<String, Set<String>> copied = new LinkedHashMap<>();
            permissionScopes.forEach((key, scopes) -> {
                if (!identifier(key, 128) || scopes == null || scopes.isEmpty() || scopes.size() > 64
                        || scopes.stream().anyMatch(scope -> scope == null || !scope.matches("[A-Za-z0-9._:-]{1,128}"))) {
                    throw new IllegalArgumentException("EXECUTION_AUTHORIZATION_POLICY_INVALID");
                }
                copied.put(key, Set.copyOf(scopes));
            });
            permissionScopes = Map.copyOf(copied);
            if (!permissionScopes.keySet().containsAll(requiredPermissions) || !permissionScopes.keySet().containsAll(sessionPermissions)) {
                throw new IllegalArgumentException("EXECUTION_AUTHORIZATION_SCOPE_BINDINGS_REQUIRED");
            }
        }
    }

    private static Set<String> permissions(Set<String> values, boolean allowEmpty) {
        if (values == null) values = Set.of();
        if ((!allowEmpty && values.isEmpty()) || values.size() > 64 || values.stream().anyMatch(value -> !identifier(value, 128))) {
            throw new IllegalArgumentException("EXECUTION_AUTHORIZATION_PERMISSIONS_INVALID");
        }
        return Set.copyOf(values);
    }

    private static boolean identifier(String value, int maximum) {
        return value != null && value.length() <= maximum && value.matches("[A-Za-z0-9][A-Za-z0-9._:/-]*");
    }

    private static boolean path(String value) {
        if (value == null || !value.matches("/[A-Za-z0-9._~/-]{1,512}") || value.contains("//")) return false;
        URI uri = URI.create(value);
        return uri.normalize().equals(uri);
    }
}
