package top.egon.cola.platform.tianquan.jianshen.starter.permission;

import org.springframework.security.authorization.AuthorizationDeniedException;
import org.springframework.security.core.context.SecurityContextHolder;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.PermissionManifest;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.ResourceAccess;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.ResourceType;
import top.egon.cola.platform.tianquan.jianshen.starter.cache.AuthorizationSnapshotLoader;
import top.egon.cola.platform.tianquan.jianshen.starter.cache.SingleFlightSnapshotLoader;
import top.egon.cola.platform.tianquan.jianshen.starter.security.CurrentRbac3User;
import top.egon.cola.platform.tianquan.jianshen.starter.security.Rbac3AuthenticationToken;
import top.egon.cola.platform.tianquan.jianshen.starter.security.Rbac3UserDetails;
import java.util.Set;
import java.util.stream.Collectors;

/** Shared API/RPC/export boundary. Scope, current SQL view and executing build are checked before the expression. */
public final class PermissionExecutionGuard {
    private final PermissionPolicyRegistry registry;
    private final CurrentRbac3User users;
    private final AuthorizationSnapshotLoader snapshots;
    private final PermissionServicePolicyGuard services;
    private final UserPermissionScopePolicy userScopes;
    private final PermissionDenialAudit audit;
    private final PermissionAnonymousBoundary anonymous;

    public PermissionExecutionGuard(PermissionPolicyRegistry registry, CurrentRbac3User users, AuthorizationSnapshotLoader snapshots) {
        this(registry, users, snapshots, null);
    }

    public PermissionExecutionGuard(PermissionPolicyRegistry registry, CurrentRbac3User users, AuthorizationSnapshotLoader snapshots,
                                     PermissionServicePolicyGuard services) {
        this(registry, users, snapshots, services,
                new top.egon.cola.platform.tianquan.jianshen.starter.autoconfigure.Rbac3StarterProperties.UserScopePolicyProperties());
    }

    public PermissionExecutionGuard(PermissionPolicyRegistry registry, CurrentRbac3User users, AuthorizationSnapshotLoader snapshots,
            PermissionServicePolicyGuard services,
            top.egon.cola.platform.tianquan.jianshen.starter.autoconfigure.Rbac3StarterProperties.UserScopePolicyProperties scopePolicy) {
        this(registry, users, snapshots, services, scopePolicy, PermissionDenialAudit.UNOBSERVED);
    }

    public PermissionExecutionGuard(PermissionPolicyRegistry registry, CurrentRbac3User users, AuthorizationSnapshotLoader snapshots,
            PermissionServicePolicyGuard services,
            top.egon.cola.platform.tianquan.jianshen.starter.autoconfigure.Rbac3StarterProperties.UserScopePolicyProperties scopePolicy,
            PermissionDenialAudit audit) {
        this(registry, users, snapshots, services, scopePolicy, audit, null);
    }

    public PermissionExecutionGuard(PermissionPolicyRegistry registry, CurrentRbac3User users, AuthorizationSnapshotLoader snapshots,
            PermissionServicePolicyGuard services,
            top.egon.cola.platform.tianquan.jianshen.starter.autoconfigure.Rbac3StarterProperties.UserScopePolicyProperties scopePolicy,
            PermissionDenialAudit audit, PermissionAnonymousBoundary anonymous) {
        this.registry = registry; this.users = users; this.snapshots = snapshots; this.services = services;
        this.userScopes = new UserPermissionScopePolicy(scopePolicy); this.audit = audit; this.anonymous = anonymous;
    }

    /** @deprecated accepts the former loader type for binary compatibility. */
    @Deprecated(since = "0.0.1", forRemoval = false)
    public PermissionExecutionGuard(PermissionPolicyRegistry registry, CurrentRbac3User users, SingleFlightSnapshotLoader snapshots) {
        this(registry, users, (AuthorizationSnapshotLoader) snapshots);
    }

    /** @deprecated accepts the former loader type for binary compatibility. */
    @Deprecated(since = "0.0.1", forRemoval = false)
    public PermissionExecutionGuard(PermissionPolicyRegistry registry, CurrentRbac3User users, SingleFlightSnapshotLoader snapshots, PermissionServicePolicyGuard services) {
        this(registry, users, (AuthorizationSnapshotLoader) snapshots, services);
    }

    /** @deprecated accepts the former loader type for binary compatibility. */
    @Deprecated(since = "0.0.1", forRemoval = false)
    public PermissionExecutionGuard(PermissionPolicyRegistry registry, CurrentRbac3User users, SingleFlightSnapshotLoader snapshots, PermissionServicePolicyGuard services, top.egon.cola.platform.tianquan.jianshen.starter.autoconfigure.Rbac3StarterProperties.UserScopePolicyProperties scopePolicy) {
        this(registry, users, (AuthorizationSnapshotLoader) snapshots, services, scopePolicy);
    }

    /** @deprecated accepts the former loader type for binary compatibility. */
    @Deprecated(since = "0.0.1", forRemoval = false)
    public PermissionExecutionGuard(PermissionPolicyRegistry registry, CurrentRbac3User users, SingleFlightSnapshotLoader snapshots, PermissionServicePolicyGuard services, top.egon.cola.platform.tianquan.jianshen.starter.autoconfigure.Rbac3StarterProperties.UserScopePolicyProperties scopePolicy, PermissionDenialAudit audit) {
        this(registry, users, (AuthorizationSnapshotLoader) snapshots, services, scopePolicy, audit);
    }

    /** @deprecated accepts the former loader type for binary compatibility. */
    @Deprecated(since = "0.0.1", forRemoval = false)
    public PermissionExecutionGuard(PermissionPolicyRegistry registry, CurrentRbac3User users, SingleFlightSnapshotLoader snapshots, PermissionServicePolicyGuard services, top.egon.cola.platform.tianquan.jianshen.starter.autoconfigure.Rbac3StarterProperties.UserScopePolicyProperties scopePolicy, PermissionDenialAudit audit, PermissionAnonymousBoundary anonymous) {
        this(registry, users, (AuthorizationSnapshotLoader) snapshots, services, scopePolicy, audit, anonymous);
    }

    public boolean nativeAnonymousBoundary(String resourceKey) { return anonymous != null && anonymous.allows(resourceKey); }

    public void requireExecution(String key) {
        var authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication != null && authentication.isAuthenticated()
                && authentication.getPrincipal() instanceof top.egon.cola.platform.tianquan.shoubing.contract.ServiceIdentityPrincipal service) {
            requireServiceApi(key, service);
        } else require(key);
    }

    public PermissionExecutionContext open(String key) {
        requireExecution(key);
        return new PermissionExecutionContext(key);
    }

    public void requireServiceApi(String key, top.egon.cola.platform.tianquan.shoubing.contract.ServiceIdentityPrincipal service) {
        var resource = registry.require(key, ResourceType.API);
        if (!resource.allowedPrincipals().contains(PermissionManifest.PrincipalType.SERVICE)
                || resource.oauthScopes().isEmpty() || !service.scopes().containsAll(resource.oauthScopes())) {
            throw audit.denied("SERVICE_SCOPE_DENIED");
        }
        if (registry.bootstrapServiceResource(key)) {
            if (!PermissionExecutionContext.verifiedService(service)) throw audit.denied("VERIFIED_SERVICE_IDENTITY_REQUIRED");
            try { registry.requireBootstrapServiceIdentity(service); }
            catch (top.egon.cola.platform.tianquan.jianshen.starter.client.Rbac3AuthorizationClient.AuthorizationDeniedException denied) { throw audit.denied(denied.getMessage()); }
        } else {
            if (services == null) throw audit.denied("SERVICE_POLICY_RUNTIME_REQUIRED");
            try { PermissionExecutionContext.verifyInput(key, services.require(service, key)); }
            catch (top.egon.cola.platform.tianquan.jianshen.starter.client.Rbac3AuthorizationClient.AuthorizationDeniedException denied) {
                throw audit.denied(denied.getMessage());
            }
        }
    }

    public Rbac3UserDetails require(String resourceKey) {
        try { return requireUser(resourceKey); }
        catch (top.egon.cola.platform.tianquan.jianshen.starter.client.Rbac3AuthorizationClient.AuthorizationDeniedException denied) {
            throw audit.denied(denied.getMessage());
        }
    }

    private Rbac3UserDetails requireUser(String resourceKey) {
        var resource = registry.require(resourceKey, ResourceType.API);
        Rbac3UserDetails current = users.require();
        var authentication = SecurityContextHolder.getContext().getAuthentication();
        Rbac3UserDetails refreshed = new Rbac3UserDetails(current.identity(), snapshots.load(current.identity()));
        registry.requireActive(refreshed.snapshot(), resourceKey);
        PermissionExecutionContext.verifyInput(resourceKey, refreshed.snapshot());
        Set<String> scopes = authentication.getAuthorities().stream().map(value -> value.getAuthority())
                .filter(value -> value.startsWith("SCOPE_")).map(value -> value.substring(6)).collect(Collectors.toSet());
        Set<String> qualifiedPermissions = userScopes.qualify(resource, refreshed.permissions(), scopes);
        if (!resource.allowedPrincipals().contains(PermissionManifest.PrincipalType.USER)
                || !userScopes.explicitScopesAllow(resource, scopes)
                || UserPermissionScopePolicy.mixed(resource) && resource.requirement() == null
                || resource.access() == ResourceAccess.PROTECTED
                   && (resource.requirement() == null || !resource.requirement().allows(qualifiedPermissions))) {
            throw audit.denied("PERMISSION_DENIED");
        }
        var replacement = new Rbac3AuthenticationToken(refreshed, authentication.getAuthorities());
        replacement.setDetails(authentication.getDetails());
        SecurityContextHolder.getContext().setAuthentication(replacement);
        return refreshed;
    }

    public PermissionManifest.ResourceDefinition resource(String resourceKey, ResourceType type) {
        return registry.require(resourceKey, type);
    }
}
