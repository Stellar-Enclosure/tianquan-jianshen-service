package top.egon.cola.platform.tianquan.jianshen.admin.registration.catalog.controller;

import top.egon.cola.component.yuheng.openapi.annotation.EgonApiCatalog;

import io.swagger.v3.oas.annotations.Operation;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.core.Authentication;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import top.egon.cola.component.common.core.pojo.ResultRecord;
import top.egon.cola.component.yuheng.openapi.annotation.EgonGatewayPolicy;
import top.egon.cola.platform.tianquan.jianshen.admin.registration.catalog.domain.PermissionCatalogCaller;
import top.egon.cola.platform.tianquan.jianshen.admin.registration.catalog.domain.convertor.PermissionCatalogJson;
import top.egon.cola.platform.tianquan.jianshen.admin.registration.catalog.service.PermissionManifestPlanService;
import top.egon.cola.platform.tianquan.jianshen.admin.registration.catalog.service.PermissionManifestRegistrationService;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.ManifestRegistrationRequest;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.PermissionManifest;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.ResourceType;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.annotation.LocalizedText;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.annotation.PermissionMessage;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.annotation.PermissionResource;
import top.egon.cola.platform.tianquan.shoubing.starter.security.RequiresServiceScope;

import java.io.IOException;
import java.util.LinkedHashMap;
import java.util.Map;

/** Machine-only plan, apply and original-outcome lookup. USER role grants use another API. */
@RestController
@EgonApiCatalog(businessDomainCode = "xingyuan", businessDomainName = "平台治理域",
        entityDomainCode = "tianquan-jianshen", entityDomainName = "RBAC3权限实体域", interfaceGroupCode = "iam")
@RequestMapping("/api/v1/permission-manifests")
@PermissionMessage(pageCode="permission.catalog", key="plan", defaultLocale="en", defaults=@LocalizedText(locale="en", text="Review permission manifest"))
@PermissionMessage(pageCode="permission.catalog", key="register", defaultLocale="en", defaults=@LocalizedText(locale="en", text="Register permission candidate"))
@PermissionMessage(pageCode="permission.catalog", key="status", defaultLocale="en", defaults=@LocalizedText(locale="en", text="Read registration outcome"))
public class PermissionManifestController {

    private static final String REGISTER_SCOPE = "tianquan-jianshen:permission-manifest:register";
    private final PermissionCatalogJson json;
    private final PermissionManifestPlanService plans;
    private final PermissionManifestRegistrationService registrations;

    public PermissionManifestController(PermissionCatalogJson json, PermissionManifestPlanService plans,
                                        PermissionManifestRegistrationService registrations) {
        this.json = json;
        this.plans = plans;
        this.registrations = registrations;
    }

    @PostMapping(value="/plans", consumes="application/json", produces="application/json")
    @RequiresServiceScope(REGISTER_SCOPE)
    @PermissionResource(key="tianquan-jianshen.api.manifest.plan", type=ResourceType.API, labelPage="permission.catalog", labelKey="plan",
            allowedPrincipals=PermissionManifest.PrincipalType.SERVICE, oauthScopes=REGISTER_SCOPE)
    @Operation(operationId="tianquan-jianshen-permission-manifest-plan-v1", summary="Review a permission manifest candidate")
    @EgonGatewayPolicy(exposure=EgonGatewayPolicy.Exposure.EXTERNAL)
    public ResultRecord<PermissionManifestPlanService.Result> plan(HttpServletRequest request, Authentication authentication) throws IOException {
        var caller = PermissionCatalogCaller.from(authentication);
        return ResultRecord.success(plans.plan(json.plan(json.readObject(request.getInputStream())), caller));
    }

    @PostMapping(value="/registrations", consumes="application/json", produces="application/json")
    @RequiresServiceScope(REGISTER_SCOPE)
    @PermissionResource(key="tianquan-jianshen.api.manifest.register", type=ResourceType.API, labelPage="permission.catalog", labelKey="register",
            allowedPrincipals=PermissionManifest.PrincipalType.SERVICE, oauthScopes=REGISTER_SCOPE)
    @Operation(operationId="tianquan-jianshen-permission-manifest-register-v1", summary="Register an immutable permission candidate")
    @EgonGatewayPolicy(exposure=EgonGatewayPolicy.Exposure.EXTERNAL)
    public ResultRecord<PermissionManifestRegistrationService.Result> register(HttpServletRequest request, Authentication authentication) throws IOException {
        var caller = PermissionCatalogCaller.from(authentication);
        return ResultRecord.success(registrations.register(json.apply(json.readObject(request.getInputStream())), caller));
    }

    @GetMapping(value="/registrations/{operationId}", produces="application/json")
    @RequiresServiceScope(REGISTER_SCOPE)
    @PermissionResource(key="tianquan-jianshen.api.manifest.status", type=ResourceType.API, labelPage="permission.catalog", labelKey="status",
            allowedPrincipals=PermissionManifest.PrincipalType.SERVICE, oauthScopes=REGISTER_SCOPE)
    @Operation(operationId="tianquan-jianshen-permission-manifest-status-v1", summary="Read original registration outcome and current readiness")
    @EgonGatewayPolicy(exposure=EgonGatewayPolicy.Exposure.EXTERNAL)
    public ResultRecord<PermissionManifestRegistrationService.Result> status(@PathVariable String operationId,
            @RequestParam MultiValueMap<String, String> query, Authentication authentication) {
        var caller = PermissionCatalogCaller.from(authentication);
        Map<String, Object> values = new LinkedHashMap<>();
        query.forEach((key, entries) -> {
            if (entries.size() != 1) throw new IllegalArgumentException("duplicate catalog query parameter");
            values.put(key, entries.getFirst());
        });
        PermissionCatalogJson.fields(values, "catalogScopeId", "tenantId", "businessCode", "applicationCode", "namespaceCode", "environment", "producerId");
        String producer = PermissionCatalogJson.text(values, "producerId");
        values.remove("producerId");
        var target = new ManifestRegistrationRequest.Target(json.scope(values), producer);
        return ResultRecord.success(registrations.status(target.target(), target.producerId(), operationId, caller));
    }
}
