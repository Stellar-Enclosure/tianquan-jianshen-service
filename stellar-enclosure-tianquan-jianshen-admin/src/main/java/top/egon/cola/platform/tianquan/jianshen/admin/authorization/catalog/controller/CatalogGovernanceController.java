package top.egon.cola.platform.tianquan.jianshen.admin.authorization.catalog.controller;

import top.egon.cola.component.yuheng.openapi.annotation.EgonApiCatalog;

import top.egon.cola.platform.tianquan.jianshen.admin.authorization.catalog.domain.vo.CatalogScopePageVO;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.catalog.domain.vo.CatalogDefinitionDetailVO;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.catalog.domain.vo.CatalogDefinitionPageVO;
import io.swagger.v3.oas.annotations.Operation;
import jakarta.validation.Valid;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import top.egon.cola.component.common.core.pojo.ResultRecord;
import top.egon.cola.component.yuheng.openapi.annotation.EgonGatewayPolicy;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.catalog.domain.dto.CatalogGovernanceCommandDTO;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.catalog.service.CatalogGovernanceService;
import top.egon.cola.platform.tianquan.jianshen.admin.registration.catalog.service.PermissionCatalogActivationService;
import top.egon.cola.platform.tianquan.jianshen.admin.registration.catalog.domain.convertor.PermissionCatalogJson;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.ResourceType;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.annotation.LocalizedText;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.annotation.PermissionMessage;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.annotation.PermissionResource;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.annotation.RequiresPermissions;
import top.egon.cola.platform.tianquan.jianshen.starter.field.StrictFieldBinding;
import top.egon.cola.platform.tianquan.jianshen.starter.security.CurrentRbac3User;

import java.util.LinkedHashMap;
import java.util.Map;

@RestController
@EgonApiCatalog(businessDomainCode = "xingyuan", businessDomainName = "平台治理域",
        entityDomainCode = "tianquan-jianshen", entityDomainName = "RBAC3权限实体域", interfaceGroupCode = "iam")
@PermissionMessage(pageCode="permission.catalog", key="scopes", defaultLocale="en", defaults=@LocalizedText(locale="en", text="Select a managed permission catalog"))
@RequestMapping("/api/v1/permission-catalogs")
@PermissionMessage(pageCode="permission.catalog", key="definitions", defaultLocale="en", defaults=@LocalizedText(locale="en", text="Read registered permission definitions"))
@PermissionMessage(pageCode="permission.catalog", key="definition", defaultLocale="en", defaults=@LocalizedText(locale="en", text="Inspect a registered permission definition"))
@PermissionMessage(pageCode="permission.catalog", key="governance", defaultLocale="en", defaults=@LocalizedText(locale="en", text="Change definition governance or ownership"))
public class CatalogGovernanceController {
    private final CatalogGovernanceService governance;
    private final PermissionCatalogJson json;

    public CatalogGovernanceController(CatalogGovernanceService governance, PermissionCatalogJson json) {
        this.governance = governance;
        this.json = json;
    }

    @GetMapping(value="/scopes", produces="application/json")
    @RequiresPermissions(codes=PermissionCatalogActivationService.READ)
    @PermissionResource(key="tianquan-jianshen.api.catalog.scopes", type=ResourceType.API, labelPage="permission.catalog", labelKey="scopes")
    @Operation(operationId="tianquan-jianshen-catalog-scopes-v1", summary="Page provisioned catalogs in the current verified tenant")
    @EgonGatewayPolicy(exposure=EgonGatewayPolicy.Exposure.EXTERNAL)
    public ResultRecord<CatalogScopePageVO> scopes(@RequestParam MultiValueMap<String, String> query) {
        var actor = new CurrentRbac3User().require();
        var values = unique(query);
        Object after = values.remove("afterId");
        Object limit = values.remove("limit");
        if (!values.isEmpty()) throw new IllegalArgumentException("catalog listing does not accept a caller-supplied tenant");
        long pageSize = limit == null ? 50 : CatalogGovernanceCommandDTO.decimal(limit.toString(), false);
        if (pageSize > 100) throw new IllegalArgumentException("catalog page size exceeds limit");
        return ResultRecord.success(governance.scopes(after == null ? 0 : CatalogGovernanceCommandDTO.decimal(after.toString(), true), (int) pageSize, actor));
    }

    @GetMapping(value="/definitions", produces="application/json")
    @RequiresPermissions(codes=PermissionCatalogActivationService.READ)
    @PermissionResource(key="tianquan-jianshen.api.catalog.definitions", type=ResourceType.API, labelPage="permission.catalog", labelKey="definitions")
    @Operation(operationId="tianquan-jianshen-catalog-definitions-v1", summary="Page stable resource or permission identities")
    @EgonGatewayPolicy(exposure=EgonGatewayPolicy.Exposure.EXTERNAL)
    public ResultRecord<CatalogDefinitionPageVO> page(@RequestParam MultiValueMap<String, String> query) {
        var actor = new CurrentRbac3User().require();
        var values = unique(query);
        var kind = CatalogGovernanceCommandDTO.Kind.valueOf(PermissionCatalogJson.text(values, "kind"));
        values.remove("kind");
        Object after = values.remove("afterId");
        Object limit = values.remove("limit");
        long pageSize = limit == null ? 50 : CatalogGovernanceCommandDTO.decimal(limit.toString(), false);
        if (pageSize > 100) throw new IllegalArgumentException("definition page size exceeds limit");
        return ResultRecord.success(governance.page(json.scope(values), kind,
                after == null ? 0 : CatalogGovernanceCommandDTO.decimal(after.toString(), true), (int) pageSize, actor));
    }

    @GetMapping(value="/definitions/{kind}/{identityId}", produces="application/json")
    @RequiresPermissions(codes=PermissionCatalogActivationService.READ)
    @PermissionResource(key="tianquan-jianshen.api.catalog.definition", type=ResourceType.API, labelPage="permission.catalog", labelKey="definition")
    @Operation(operationId="tianquan-jianshen-catalog-definition-v1", summary="Read current immutable definition and governance state")
    @EgonGatewayPolicy(exposure=EgonGatewayPolicy.Exposure.EXTERNAL)
    public ResultRecord<CatalogDefinitionDetailVO> detail(@PathVariable String kind, @PathVariable String identityId,
            @RequestParam MultiValueMap<String, String> query) {
        var actor = new CurrentRbac3User().require();
        return ResultRecord.success(governance.detail(json.scope(unique(query)), CatalogGovernanceCommandDTO.Kind.valueOf(kind),
                CatalogGovernanceCommandDTO.decimal(identityId, false), actor));
    }

    @PostMapping(value="/governance", consumes="application/json", produces="application/json")
    @RequiresPermissions(codes=PermissionCatalogActivationService.MANAGE)
    @PermissionResource(key="tianquan-jianshen.api.catalog.governance", type=ResourceType.API, labelPage="permission.catalog", labelKey="governance")
    @Operation(operationId="tianquan-jianshen-catalog-governance-v1", summary="Disable, retire or explicitly transfer a stable identity")
    @EgonGatewayPolicy(exposure=EgonGatewayPolicy.Exposure.EXTERNAL)
    public ResultRecord<CatalogGovernanceService.Result> mutate(
            @Valid @RequestBody @StrictFieldBinding(requiredFields = {"target", "kind", "identityId", "action", "expectedVersion"}) CatalogGovernanceCommandDTO request) {
        var actor = new CurrentRbac3User().require();
        return ResultRecord.success(governance.mutate(request, actor));
    }

    private Map<String, Object> unique(MultiValueMap<String, String> query) {
        Map<String, Object> result = new LinkedHashMap<>();
        query.forEach((key, values) -> {
            if (values.size() != 1) throw new IllegalArgumentException("duplicate catalog query parameter");
            result.put(key, values.getFirst());
        });
        return result;
    }
}
