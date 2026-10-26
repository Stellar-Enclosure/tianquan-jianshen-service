package top.egon.cola.platform.tianquan.jianshen.starter.permission;

import org.springframework.core.annotation.AnnotatedElementUtils;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import org.springframework.web.method.HandlerMethod;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.annotation.PermissionResource;

/** Bounded explicit adapter context; HTTP uses Spring's selected handler, never a caller-supplied header. */
public final class PermissionExecutionContext implements AutoCloseable {
    private static final String INPUT_CHECKPOINT = PermissionExecutionContext.class.getName() + ".inputCheckpoint";
    private static final ThreadLocal<PermissionExecutionContext> API = new ThreadLocal<>();
    private final PermissionExecutionContext previous;
    private final String apiKey;
    private final java.util.Map<String, java.util.List<Object>> inputCheckpoints = new java.util.HashMap<>();
    private boolean closed;

    PermissionExecutionContext(String verifiedApiKey) {
        previous = API.get(); apiKey = verifiedApiKey; API.set(this);
    }

    public static String currentApiKey() {
        String key = apiKeyOrNull();
        if (key == null) throw new org.springframework.security.authorization.AuthorizationDeniedException("FIELD_API_BOUNDARY_REQUIRED");
        return key;
    }

    private static String apiKeyOrNull() {
        if (API.get() != null) return API.get().apiKey;
        var attributes = RequestContextHolder.getRequestAttributes();
        if (attributes instanceof ServletRequestAttributes servlet
                && servlet.getRequest().getAttribute("org.springframework.web.servlet.HandlerMapping.bestMatchingHandler") instanceof HandlerMethod handler) {
            PermissionResource resource = AnnotatedElementUtils.findMergedAnnotation(handler.getMethod(), PermissionResource.class);
            if (resource != null) return resource.key();
        }
        return null;
    }

    public static boolean verifiedService(top.egon.cola.platform.tianquan.shoubing.contract.ServiceIdentityPrincipal caller) {
        var authentication = org.springframework.security.core.context.SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null || !authentication.isAuthenticated() || authentication.getPrincipal() != caller) return false;
        if (authentication instanceof top.egon.cola.platform.tianquan.shoubing.starter.security.IdpAuthenticationToken token) {
            try { if (token.verifiedIssuer() != null) return true; }
            catch (IllegalStateException missing) { if (!"VERIFIED_ISSUER_UNAVAILABLE".equals(missing.getMessage())) throw missing; }
        }
        var proof = top.egon.cola.platform.tianquan.shoubing.starter.security.rpc.IdpRpcSecurityContext.currentProofOrNull();
        return top.egon.cola.platform.tianquan.shoubing.starter.security.rpc.IdpRpcSecurityContext.currentPrincipalOrNull() == caller
                && proof != null && proof.equals(authentication.getDetails()) && proof.resource().equals(caller.resourceUri());
    }

    /** A binder conclusion cannot survive a different SQL view at the later method boundary. */
    public static void rememberInput(top.egon.cola.platform.tianquan.jianshen.contract.authorization.SystemAuthorizationSnapshot snapshot) {
        checkpoint(apiKeyOrNull(), userStamp(snapshot), true);
    }

    public static void rememberInput(top.egon.cola.platform.tianquan.jianshen.contract.authorization.ServicePolicySnapshot snapshot) {
        checkpoint(apiKeyOrNull(), serviceStamp(snapshot), true);
    }

    public static void verifyInput(String key, top.egon.cola.platform.tianquan.jianshen.contract.authorization.SystemAuthorizationSnapshot snapshot) {
        checkpoint(key, userStamp(snapshot), false);
    }

    public static void verifyInput(String key, top.egon.cola.platform.tianquan.jianshen.contract.authorization.ServicePolicySnapshot snapshot) {
        checkpoint(key, serviceStamp(snapshot), false);
    }

    private static java.util.List<Object> userStamp(top.egon.cola.platform.tianquan.jianshen.contract.authorization.SystemAuthorizationSnapshot snapshot) {
        var view = snapshot.permissionSnapshot();
        return java.util.List.of("USER", view.issuer(), view.subject(), view.catalogScope(), view.catalogVersion(),
                view.authVersion(), view.policyVersion(), view.activeRoleContext(), view.permissionCodes(),
                snapshot.policyBinding(), snapshot.resourceCodes());
    }

    private static java.util.List<Object> serviceStamp(top.egon.cola.platform.tianquan.jianshen.contract.authorization.ServicePolicySnapshot snapshot) {
        return java.util.List.of("SERVICE", snapshot.catalogScope(), snapshot.catalogVersion(), snapshot.policyVersion(),
                snapshot.policyBinding(), snapshot.resourceKeys());
    }

    @SuppressWarnings("unchecked")
    private static void checkpoint(String key, java.util.List<Object> stamp, boolean remember) {
        if (key == null) return;
        java.util.Map<String, java.util.List<Object>> checkpoints;
        if (API.get() != null) checkpoints = API.get().inputCheckpoints;
        else if (RequestContextHolder.getRequestAttributes() instanceof ServletRequestAttributes servlet) {
            var request = servlet.getRequest();
            checkpoints = (java.util.Map<String, java.util.List<Object>>) request.getAttribute(INPUT_CHECKPOINT);
            if (checkpoints == null) {
                if (!remember) return;
                checkpoints = new java.util.HashMap<>(); request.setAttribute(INPUT_CHECKPOINT, checkpoints);
            }
        } else return;
        var earlier = checkpoints.get(key);
        if (earlier != null && !earlier.equals(stamp)) {
            throw new top.egon.cola.platform.tianquan.jianshen.starter.client.Rbac3AuthorizationClient.AuthorizationUnavailableException(
                    "FIELD_AUTHORIZATION_VIEW_CHANGED", null);
        }
        if (remember && earlier == null) checkpoints.put(key, stamp);
    }

    @Override public void close() {
        if (closed) return;
        closed = true;
        if (previous == null) API.remove(); else API.set(previous);
    }
}
