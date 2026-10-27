package top.egon.cola.platform.tianquan.jianshen.starter.permission;

import top.egon.cola.platform.tianquan.jianshen.contract.permission.PermissionManifest;
import top.egon.cola.platform.tianquan.jianshen.starter.autoconfigure.Rbac3StarterProperties;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

/** A permission participates in ALL/ANY only after its USER Scope upper bound is satisfied. */
public final class UserPermissionScopePolicy {
    private final boolean enabled;
    private final Map<String, Set<String>> mappings;

    public UserPermissionScopePolicy(Rbac3StarterProperties.UserScopePolicyProperties properties) {
        enabled = properties.isEnabled();
        mappings = properties.getPermissionScopes().entrySet().stream().collect(Collectors.toUnmodifiableMap(
                Map.Entry::getKey, entry -> Set.copyOf(entry.getValue())));
    }

    public Set<String> qualify(PermissionManifest.ResourceDefinition resource, Set<String> granted, Set<String> scopes) {
        boolean mixed = mixed(resource);
        if (mixed && !enabled) return Set.of();
        if (!enabled) return granted;
        return granted.stream().filter(code -> mappings.containsKey(code) ? scopes.containsAll(mappings.get(code))
                : !mixed && !resource.oauthScopes().isEmpty()).collect(Collectors.toUnmodifiableSet());
    }

    public boolean explicitScopesAllow(PermissionManifest.ResourceDefinition resource, Set<String> scopes) {
        return mixed(resource) || scopes.containsAll(resource.oauthScopes());
    }

    boolean hasScopeMapping(String permission) { return enabled && mappings.containsKey(permission); }

    Set<String> missingScopes(String permission, Set<String> scopes) {
        if (!hasScopeMapping(permission)) return Set.of();
        return mappings.get(permission).stream().filter(scope -> !scopes.contains(scope))
                .collect(Collectors.toUnmodifiableSet());
    }

    public static boolean mixed(PermissionManifest.ResourceDefinition resource) {
        return resource.allowedPrincipals().contains(PermissionManifest.PrincipalType.USER)
                && resource.allowedPrincipals().contains(PermissionManifest.PrincipalType.SERVICE);
    }

    public static Set<String> currentScopes() {
        var authentication = org.springframework.security.core.context.SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null || !authentication.isAuthenticated()) return Set.of();
        return authentication.getAuthorities().stream().map(authority -> authority.getAuthority())
                .filter(value -> value != null && value.startsWith("SCOPE_")).map(value -> value.substring(6)).collect(Collectors.toUnmodifiableSet());
    }
}
