package top.egon.cola.platform.tianquan.jianshen.starter.permission;

import java.util.Set;
import java.util.function.Supplier;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.PermissionManifest;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.ResourceAccess;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.ResourceType;
import top.egon.cola.platform.tianquan.shoubing.starter.security.IdpEndpointAuthenticationPolicy;

/** The reviewed native login-text boundary is independent of USER Runtime; PUBLIC alone grants no anonymous access. */
public final class PermissionAnonymousBoundary {
    public static final String LOGIN_TEXT_KEY = "tianshu.api.adminUiI18n.publicBundle";
    private static final String LOGIN_TEXT_PATH = "/api/v1/tianshu/i18n/public/bundle";
    private static final String LOGIN_TEXT_DTO = "top.egon.cola.component.tianshu.admin.model.vo.DdcPublicI18nBundleResult";
    private final PermissionPolicyRegistry registry;
    private final Supplier<IdpEndpointAuthenticationPolicy> endpointPolicy;

    public PermissionAnonymousBoundary(PermissionPolicyRegistry registry, Supplier<IdpEndpointAuthenticationPolicy> endpointPolicy) {
        this.registry = registry; this.endpointPolicy = endpointPolicy;
    }

    public boolean allows(String key) {
        if (!LOGIN_TEXT_KEY.equals(key) || !registry.anonymousResource(key)
                || !(RequestContextHolder.getRequestAttributes() instanceof ServletRequestAttributes servlet)) return false;
        var request = servlet.getRequest();
        String path = request.getRequestURI().substring(request.getContextPath().length());
        var classifier = endpointPolicy.get();
        if (!"GET".equals(request.getMethod()) || !LOGIN_TEXT_PATH.equals(path) || classifier == null
                || classifier.requirement(request) != IdpEndpointAuthenticationPolicy.Requirement.PUBLIC) return false;
        if (request.getParameterMap().keySet().stream().anyMatch(name -> !"locale".equals(name))
                || request.getParameterMap().values().stream().anyMatch(values -> values.length != 1)) return false;
        var resource = registry.require(key, ResourceType.API);
        return resource.access() == ResourceAccess.PUBLIC && resource.requirement() == null;
    }

    public boolean readOnlyField(PermissionManifest.ResourceDefinition field, boolean actualReadOnly) {
        if (!actualReadOnly || field.access() != ResourceAccess.PUBLIC || !LOGIN_TEXT_DTO.equals(field.target().get("dto"))
                || !Set.of("pageCode", "locale", "defaultLocale", "version", "messages").contains(field.target().get("property"))) return false;
        try { return allows(PermissionExecutionContext.currentApiKey()); }
        catch (org.springframework.security.authorization.AuthorizationDeniedException absent) { return false; }
    }
}
