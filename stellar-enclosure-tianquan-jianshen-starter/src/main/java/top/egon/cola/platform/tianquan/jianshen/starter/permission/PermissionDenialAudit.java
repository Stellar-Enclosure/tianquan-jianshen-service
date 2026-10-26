package top.egon.cola.platform.tianquan.jianshen.starter.permission;

import java.util.function.Supplier;
import org.springframework.security.authorization.AuthorizationDeniedException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import top.egon.cola.platform.tianquan.jianshen.starter.client.Rbac3AuthorizationClient;
import top.egon.cola.platform.tianquan.shoubing.starter.security.IdpObservedVerificationComponent;
import top.egon.cola.platform.tianquan.shoubing.starter.security.IdpSecurityObservationFilter;
import top.egon.cola.platform.tianquan.shoubing.starter.security.domain.TokenAuditProofBO;
import top.egon.cola.platform.tianquan.shoubing.starter.security.rpc.IdpRpcSecurityContext;

/** Reuses the existing per-invocation strict audit marker for compiled API, field and alternative-entry denials. */
public final class PermissionDenialAudit {
    public static final PermissionDenialAudit UNOBSERVED = new PermissionDenialAudit(() -> null);
    private final Supplier<IdpObservedVerificationComponent> observations;

    public PermissionDenialAudit(Supplier<IdpObservedVerificationComponent> observations) { this.observations = observations; }

    public RuntimeException denied(String reason) {
        boolean confirmed = true;
        if (RequestContextHolder.getRequestAttributes() instanceof ServletRequestAttributes servlet) {
            confirmed = IdpSecurityObservationFilter.beforeAuthorizationDenied(servlet.getRequest());
        } else {
            var observer = observations.get();
            if (observer != null && observer.enabled()) {
                var authentication = SecurityContextHolder.getContext().getAuthentication();
                TokenAuditProofBO proof = IdpRpcSecurityContext.currentProofOrNull();
                if (proof == null && authentication != null && authentication.getDetails() instanceof TokenAuditProofBO details) proof = details;
                if (proof == null) confirmed = false;
                else {
                    var verified = proof;
                    var marker = IdpRpcSecurityContext.currentAuthorizationObservationContext();
                    confirmed = marker == null ? observer.authorizationDenied(verified)
                            : marker.denyOnce(() -> observer.authorizationDenied(verified));
                }
            }
        }
        return confirmed ? new AuthorizationDeniedException(reason)
                : new Rbac3AuthorizationClient.AuthorizationUnavailableException("OAUTH_AUDIT_DELIVERY_UNAVAILABLE");
    }
}
