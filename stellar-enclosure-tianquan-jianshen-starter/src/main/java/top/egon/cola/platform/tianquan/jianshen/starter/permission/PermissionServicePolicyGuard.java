package top.egon.cola.platform.tianquan.jianshen.starter.permission;

import top.egon.cola.platform.tianquan.shoubing.contract.ServiceIdentityPrincipal;
import top.egon.cola.platform.tianquan.jianshen.contract.authorization.ServicePolicySnapshot;
import top.egon.cola.platform.tianquan.jianshen.starter.client.Rbac3AuthorizationClient;

/** The executing host uses its fixed SERVICE credential to inspect current policy; no USER is synthesized. */
public final class PermissionServicePolicyGuard {
    private final PermissionPolicyRegistry registry;
    private final Rbac3AuthorizationClient client;
    private final String systemCode;
    private final java.time.Clock clock;

    public PermissionServicePolicyGuard(PermissionPolicyRegistry registry, Rbac3AuthorizationClient client, String systemCode) {
        this(registry, client, systemCode, java.time.Clock.systemUTC());
    }

    public PermissionServicePolicyGuard(PermissionPolicyRegistry registry, Rbac3AuthorizationClient client, String systemCode, java.time.Clock clock) {
        this.registry = registry; this.client = client; this.systemCode = systemCode; this.clock = clock;
    }

    public ServicePolicySnapshot require(ServiceIdentityPrincipal principal, String resourceKey) {
        if (principal == null || principal.tenantId() == null || !principal.expiresAt().isAfter(clock.instant())
                || !PermissionExecutionContext.verifiedService(principal)) {
            throw new Rbac3AuthorizationClient.AuthorizationDeniedException("SERVICE_IDENTITY_DENIED");
        }
        try {
            ServicePolicySnapshot policy = client.fetchPolicy(systemCode, principal);
            registry.requireActive(policy, resourceKey);
            if (!principal.tenantId().equals(policy.catalogScope().tenantId())) {
                throw new Rbac3AuthorizationClient.AuthorizationDeniedException("SERVICE_POLICY_BINDING_MISMATCH");
            }
            return policy;
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
            throw new Rbac3AuthorizationClient.AuthorizationUnavailableException("SERVICE_POLICY_RUNTIME_UNAVAILABLE", interrupted);
        }
    }
}
