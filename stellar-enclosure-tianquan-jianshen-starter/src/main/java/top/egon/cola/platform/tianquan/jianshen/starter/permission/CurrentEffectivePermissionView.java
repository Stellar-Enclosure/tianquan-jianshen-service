package top.egon.cola.platform.tianquan.jianshen.starter.permission;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.EffectivePermissionSnapshot;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.ResourceType;
import top.egon.cola.platform.tianquan.jianshen.starter.client.Rbac3AuthorizationClient;
import top.egon.cola.platform.tianquan.jianshen.starter.security.CurrentRbac3User;
import top.egon.cola.platform.tianquan.shoubing.starter.security.VerifiedUserTokenCarrier;
import java.time.Clock;

/** Projects the request's already verified SQL view; every host declares its own USER endpoint/resource key. */
public final class CurrentEffectivePermissionView {
    private final CurrentRbac3User users;
    private final PermissionPolicyRegistry policies;
    private final Clock clock;

    public CurrentEffectivePermissionView(CurrentRbac3User users, PermissionPolicyRegistry policies, Clock clock) {
        this.users = users; this.policies = policies; this.clock = clock;
    }

    public EffectivePermissionSnapshot current(HttpServletRequest request, String hostResourceKey) {
        if (!request.getParameterMap().isEmpty()) throw new IllegalArgumentException("permission view does not accept query parameters");
        return boundCurrent(request, hostResourceKey);
    }

    EffectivePermissionSnapshot boundCurrent(HttpServletRequest request, String hostResourceKey) {
        var user = users.require();
        try { VerifiedUserTokenCarrier.current(request); }
        catch (IllegalStateException missing) { throw new AuthenticationCredentialsNotFoundException("VERIFIED_USER_PROOF_REQUIRED"); }
        if (!user.identity().expiresAt().isAfter(clock.instant())) throw new AuthenticationCredentialsNotFoundException("JWT_EXPIRED");
        var snapshot = user.snapshot();
        var view = snapshot.permissionSnapshot();
        if (view == null || snapshot.policyBinding() == null || !snapshot.expiresAt().isAfter(clock.instant())
                || snapshot.expiresAt().isAfter(user.identity().expiresAt())) {
            throw new Rbac3AuthorizationClient.AuthorizationUnavailableException("AUTH_SNAPSHOT_NOT_READY");
        }
        var resource = policies.require(hostResourceKey, ResourceType.API);
        if (!resource.allowedPrincipals().contains(top.egon.cola.platform.tianquan.jianshen.contract.permission.PermissionManifest.PrincipalType.USER)) {
            throw new Rbac3AuthorizationClient.AuthorizationDeniedException("USER_PERMISSION_VIEW_REQUIRED");
        }
        policies.requireActive(snapshot, hostResourceKey);
        return view;
    }
}
