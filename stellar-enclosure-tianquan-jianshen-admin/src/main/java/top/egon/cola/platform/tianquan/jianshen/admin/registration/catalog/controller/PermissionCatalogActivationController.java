package top.egon.cola.platform.tianquan.jianshen.admin.registration.catalog.controller;

import top.egon.cola.component.yuheng.openapi.annotation.EgonApiCatalog;

import top.egon.cola.platform.tianquan.jianshen.admin.registration.catalog.domain.vo.DeploymentQualificationReceiptVO;
import io.swagger.v3.oas.annotations.Operation;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.core.Authentication;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import top.egon.cola.component.common.core.pojo.ResultRecord;
import top.egon.cola.component.yuheng.openapi.annotation.EgonGatewayPolicy;
import top.egon.cola.platform.tianquan.jianshen.admin.registration.catalog.domain.PermissionCatalogCaller;
import top.egon.cola.platform.tianquan.jianshen.admin.registration.catalog.service.DeploymentQualificationService;
import top.egon.cola.platform.tianquan.jianshen.admin.registration.catalog.service.PermissionCatalogActivationService;
import top.egon.cola.platform.tianquan.jianshen.admin.registration.catalog.domain.convertor.PermissionCatalogJson;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.ActivationDescriptor;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.CatalogActivationRequest;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.DeploymentQualificationRequest;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.ManifestRegistrationRequest;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.PermissionManifest;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.ResourceType;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.annotation.LocalizedText;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.annotation.PermissionMessage;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.annotation.PermissionResource;
import top.egon.cola.platform.tianquan.shoubing.starter.security.RequiresServiceScope;

import top.egon.cola.platform.tianquan.jianshen.starter.security.Rbac3UserDetails;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.annotation.PermissionDefinition;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.annotation.RequiresPermissions;
import org.springframework.security.access.prepost.PreAuthorize;
import java.io.IOException;
import java.util.LinkedHashMap;
import java.util.Map;

@RestController
@EgonApiCatalog(businessDomainCode = "xingyuan", businessDomainName = "平台治理域",
        entityDomainCode = "tianquan-jianshen", entityDomainName = "RBAC3权限实体域", interfaceGroupCode = "iam")
@PermissionDefinition(code=PermissionCatalogActivationService.READ, meaning="Read managed tenant catalog versions and definitions", labelPage="permission.catalog", labelKey="versions")
@PermissionDefinition(code=PermissionCatalogActivationService.ACTIVATE, meaning="Activate a qualified permission catalog in the managed tenant", labelPage="permission.catalog", labelKey="activate")
@PermissionDefinition(code=PermissionCatalogActivationService.MANAGE, meaning="Approve capability expansion and govern catalog identities in the managed tenant", labelPage="permission.catalog", labelKey="manage")
@PermissionMessage(pageCode="permission.catalog", key="manage", defaultLocale="en", defaults=@LocalizedText(locale="en", text="Manage permission catalog governance"))
@PermissionMessage(pageCode="permission.catalog", key="activate", defaultLocale="en", defaults=@LocalizedText(locale="en", text="Activate a qualified permission catalog"))
@PermissionMessage(pageCode="permission.catalog", key="qualify", defaultLocale="en", defaults=@LocalizedText(locale="en", text="Attest deployment readiness"))
@PermissionMessage(pageCode="permission.catalog", key="versions", defaultLocale="en", defaults=@LocalizedText(locale="en", text="Read permission catalog history"))
@PermissionMessage(pageCode="permission.catalog", key="descriptor", defaultLocale="en", defaults=@LocalizedText(locale="en", text="Read a permission activation descriptor"))
public class PermissionCatalogActivationController {
    private static final String ACTIVATE = "tianquan-jianshen:permission-catalog:activate";
    private static final String READ = "tianquan-jianshen:permission-catalog:read";
    private static final String QUALIFY = "tianquan-jianshen:permission-catalog:qualify";
    private final PermissionCatalogJson json;
    private final PermissionCatalogActivationService activations;
    private final DeploymentQualificationService qualifications;

    public PermissionCatalogActivationController(PermissionCatalogJson json, PermissionCatalogActivationService activations,
                                                 DeploymentQualificationService qualifications) {
        this.json = json;
        this.activations = activations;
        this.qualifications = qualifications;
    }

    @PostMapping(value="/api/v1/permission-catalogs/activations", consumes="application/json", produces="application/json")
    @RequiresPermissions(codes=PermissionCatalogActivationService.ACTIVATE)
    @PreAuthorize("@serviceScopeAuthorization.hasScope(authentication, 'tianquan-jianshen:permission-catalog:activate') or (principal instanceof T(top.egon.cola.platform.tianquan.jianshen.starter.security.Rbac3UserDetails) and principal.hasPermission('system:permission-catalog:activate'))")
    @PermissionResource(key="tianquan-jianshen.api.catalog.activate", type=ResourceType.API, labelPage="permission.catalog", labelKey="activate",
            allowedPrincipals={PermissionManifest.PrincipalType.USER, PermissionManifest.PrincipalType.SERVICE}, oauthScopes=ACTIVATE)
    @Operation(operationId="tianquan-jianshen-permission-catalog-activate-v1", summary="Activate a complete qualified producer set")
    @EgonGatewayPolicy(exposure=EgonGatewayPolicy.Exposure.EXTERNAL)
    public ResultRecord<ActivationDescriptor> activate(HttpServletRequest request, Authentication authentication) throws IOException {
        var body = json.readObject(request.getInputStream());
        PermissionCatalogJson.fields(body, "target", "operationId", "expectedActiveRevision", "producers");
        var command = json.read(json.write(body), CatalogActivationRequest.class);
        if (authentication.getPrincipal() instanceof Rbac3UserDetails actor) {
            return ResultRecord.success(activations.activateAdministrator(command, actor));
        }
        return ResultRecord.success(activations.activate(command, PermissionCatalogCaller.from(authentication)));
    }

    @PostMapping(value="/internal/v1/permission-catalogs/deployment-qualifications", consumes="application/json", produces="application/json")
    @RequiresServiceScope(QUALIFY)
    @PermissionResource(key="tianquan-jianshen.api.catalog.qualify", type=ResourceType.API, labelPage="permission.catalog", labelKey="qualify",
            allowedPrincipals=PermissionManifest.PrincipalType.SERVICE, oauthScopes=QUALIFY)
    @Operation(operationId="tianquan-jianshen-permission-catalog-qualify-v1", summary="Record trusted deployment readiness")
    @EgonGatewayPolicy(exposure=EgonGatewayPolicy.Exposure.INTERNAL)
    public ResultRecord<DeploymentQualificationReceiptVO> qualify(HttpServletRequest request, Authentication authentication) throws IOException {
        var caller = PermissionCatalogCaller.from(authentication);
        var body = json.readObject(request.getInputStream());
        PermissionCatalogJson.fields(body, "target", "producerId", "producerVersion", "artifactDigest", "manifestDigest", "policyDigest",
                "pipelineId", "buildId", "sourceRef", "commit", "deploymentId", "readiness");
        return ResultRecord.success(qualifications.qualify(json.read(json.write(body), DeploymentQualificationRequest.class), caller));
    }

    @GetMapping(value="/api/v1/permission-catalogs/versions", produces="application/json")
    @RequiresPermissions(codes=PermissionCatalogActivationService.READ)
    @PreAuthorize("@serviceScopeAuthorization.hasScope(authentication, 'tianquan-jianshen:permission-catalog:read') or (principal instanceof T(top.egon.cola.platform.tianquan.jianshen.starter.security.Rbac3UserDetails) and principal.hasPermission('system:permission-catalog:read'))")
    @PermissionResource(key="tianquan-jianshen.api.catalog.versions", type=ResourceType.API, labelPage="permission.catalog", labelKey="versions",
            allowedPrincipals={PermissionManifest.PrincipalType.USER, PermissionManifest.PrincipalType.SERVICE}, oauthScopes=READ)
    @Operation(operationId="tianquan-jianshen-permission-catalog-versions-v1", summary="Read immutable versions or an original activation outcome")
    @EgonGatewayPolicy(exposure=EgonGatewayPolicy.Exposure.EXTERNAL)
    public ResultRecord<?> versions(@RequestParam MultiValueMap<String, String> query, Authentication authentication) {
        Map<String, Object> values = unique(query);
        Object operation = values.remove("operationId");
        Object before = values.remove("beforeVersion");
        Object limit = values.remove("limit");
        String producer = (String) values.remove("producerId");
        var scope = json.scope(values);
        Rbac3UserDetails actor = authentication.getPrincipal() instanceof Rbac3UserDetails user ? user : null;
        var caller = actor == null ? PermissionCatalogCaller.from(authentication) : null;
        if (caller != null) producer = new ManifestRegistrationRequest.Target(scope, producer).producerId();
        if (operation != null) {
            if (before != null || limit != null) throw new IllegalArgumentException("operation lookup cannot be paged");
            return ResultRecord.success(actor == null ? activations.operation(scope, producer, operation.toString(), caller)
                    : activations.administratorOperation(scope, operation.toString(), actor));
        }
        long beforeVersion = before == null ? 0 : decimal(before.toString(), true);
        long pageSize = limit == null ? 20 : decimal(limit.toString(), false);
        if (pageSize > 50) throw new IllegalArgumentException("activation page size exceeds limit");
        return ResultRecord.success(actor == null ? activations.history(scope, producer, beforeVersion, (int) pageSize, caller)
                : activations.administratorHistory(scope, beforeVersion, (int) pageSize, actor));
    }

    @GetMapping(value="/internal/v1/permission-catalogs/{catalogScopeId}/activations/{version}", produces="application/json")
    @RequiresServiceScope(READ)
    @PermissionResource(key="tianquan-jianshen.api.catalog.descriptor", type=ResourceType.API, labelPage="permission.catalog", labelKey="descriptor",
            allowedPrincipals=PermissionManifest.PrincipalType.SERVICE, oauthScopes=READ)
    @Operation(operationId="tianquan-jianshen-permission-catalog-descriptor-v1", summary="Read one immutable activation descriptor")
    @EgonGatewayPolicy(exposure=EgonGatewayPolicy.Exposure.INTERNAL)
    public ResultRecord<ActivationDescriptor> descriptor(@PathVariable String catalogScopeId, @PathVariable String version,
            @RequestParam MultiValueMap<String, String> query, Authentication authentication) {
        var caller = PermissionCatalogCaller.from(authentication);
        var target = target(unique(query));
        if (!catalogScopeId.equals(target.target().catalogScopeId())) throw new IllegalArgumentException("catalog path and target differ");
        return ResultRecord.success(activations.descriptor(target.target(), target.producerId(), decimal(version, false), caller));
    }

    private ManifestRegistrationRequest.Target target(Map<String, Object> values) {
        PermissionCatalogJson.fields(values, "catalogScopeId", "tenantId", "businessCode", "applicationCode", "namespaceCode", "environment", "producerId");
        String producer = PermissionCatalogJson.text(values, "producerId");
        values.remove("producerId");
        return new ManifestRegistrationRequest.Target(json.scope(values), producer);
    }

    private Map<String, Object> unique(MultiValueMap<String, String> query) {
        Map<String, Object> values = new LinkedHashMap<>();
        query.forEach((key, entries) -> {
            if (entries.size() != 1) throw new IllegalArgumentException("duplicate catalog query parameter");
            values.put(key, entries.getFirst());
        });
        return values;
    }

    private long decimal(String value, boolean zero) {
        if (value == null || !value.matches(zero ? "0|[1-9][0-9]{0,18}" : "[1-9][0-9]{0,18}")) throw new IllegalArgumentException("invalid catalog number");
        return Long.parseLong(value);
    }
}
