package top.egon.cola.platform.tianquan.jianshen.admin.registration.catalog.controller;

import io.swagger.v3.oas.annotations.Operation;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import top.egon.cola.component.common.core.pojo.ResultRecord;
import top.egon.cola.component.yuheng.openapi.annotation.EgonGatewayPolicy;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.catalog.domain.dto.CatalogGovernanceCommandDTO;
import top.egon.cola.platform.tianquan.jianshen.admin.registration.catalog.service.PermissionCatalogActivationService;
import top.egon.cola.platform.tianquan.jianshen.admin.registration.catalog.domain.convertor.PermissionCatalogJson;
import top.egon.cola.platform.tianquan.jianshen.admin.registration.catalog.service.PermissionCatalogQueryService;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.ResourceType;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.annotation.LocalizedText;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.annotation.PermissionMessage;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.annotation.PermissionResource;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.annotation.RequiresPermissions;
import top.egon.cola.platform.tianquan.jianshen.starter.security.CurrentRbac3User;

import java.util.LinkedHashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/v1/permission-catalogs")
@PermissionMessage(pageCode="permission.catalog", key="producers", defaultLocale="en", defaults=@LocalizedText(locale="en", text="Read catalog producers"))
@PermissionMessage(pageCode="permission.catalog", key="candidates", defaultLocale="en", defaults=@LocalizedText(locale="en", text="Review catalog candidates and deployment readiness"))
@PermissionMessage(pageCode="permission.catalog", key="diff", defaultLocale="en", defaults=@LocalizedText(locale="en", text="Compare a candidate with the active catalog"))
public class PermissionCatalogQueryController {
    private final PermissionCatalogQueryService queries;
    private final PermissionCatalogJson json;

    public PermissionCatalogQueryController(PermissionCatalogQueryService queries, PermissionCatalogJson json) {
        this.queries = queries;
        this.json = json;
    }

    @GetMapping(value="/producers", produces="application/json")
    @RequiresPermissions(codes=PermissionCatalogActivationService.READ)
    @PermissionResource(key="tianquan-jianshen.api.catalog.producers", type=ResourceType.API, labelPage="permission.catalog", labelKey="producers")
    @Operation(operationId="tianquan-jianshen-catalog-producers-v1", summary="Read the complete enabled producer set and current revisions")
    @EgonGatewayPolicy(exposure=EgonGatewayPolicy.Exposure.EXTERNAL)
    public ResultRecord<PermissionCatalogQueryService.Producers> producers(@RequestParam MultiValueMap<String, String> query) {
        return ResultRecord.success(queries.producers(json.scope(unique(query)), new CurrentRbac3User().require()));
    }

    @GetMapping(value="/candidates", produces="application/json")
    @RequiresPermissions(codes=PermissionCatalogActivationService.READ)
    @PermissionResource(key="tianquan-jianshen.api.catalog.candidates", type=ResourceType.API, labelPage="permission.catalog", labelKey="candidates")
    @Operation(operationId="tianquan-jianshen-catalog-candidates-v1", summary="Page immutable candidates and current trusted qualifications")
    @EgonGatewayPolicy(exposure=EgonGatewayPolicy.Exposure.EXTERNAL)
    public ResultRecord<PermissionCatalogQueryService.Candidates> candidates(@RequestParam MultiValueMap<String, String> query) {
        var actor = new CurrentRbac3User().require();
        var values = unique(query);
        String producerId = PermissionCatalogJson.text(values, "producerId");
        values.remove("producerId");
        Object before = values.remove("beforeVersion");
        Object limit = values.remove("limit");
        long pageSize = limit == null ? 20 : CatalogGovernanceCommandDTO.decimal(limit.toString(), false);
        if (pageSize > 50) throw new IllegalArgumentException("candidate page size exceeds limit");
        return ResultRecord.success(queries.candidates(json.scope(values), producerId,
                before == null ? 0 : CatalogGovernanceCommandDTO.decimal(before.toString(), true), (int) pageSize, actor));
    }

    @GetMapping(value="/diff", produces="application/json")
    @RequiresPermissions(codes=PermissionCatalogActivationService.READ)
    @PermissionResource(key="tianquan-jianshen.api.catalog.diff", type=ResourceType.API, labelPage="permission.catalog", labelKey="diff")
    @Operation(operationId="tianquan-jianshen-catalog-diff-v1", summary="Recalculate authorization expansion against the current active version")
    @EgonGatewayPolicy(exposure=EgonGatewayPolicy.Exposure.EXTERNAL)
    public ResultRecord<PermissionCatalogQueryService.Diff> diff(@RequestParam MultiValueMap<String, String> query) {
        var actor = new CurrentRbac3User().require();
        var values = unique(query);
        String producerId = PermissionCatalogJson.text(values, "producerId");
        String producerVersion = PermissionCatalogJson.text(values, "producerVersion");
        values.remove("producerId");
        values.remove("producerVersion");
        return ResultRecord.success(queries.diff(json.scope(values), producerId, CatalogGovernanceCommandDTO.decimal(producerVersion, false), actor));
    }

    private Map<String, Object> unique(MultiValueMap<String, String> query) {
        Map<String, Object> values = new LinkedHashMap<>();
        query.forEach((key, entries) -> {
            if (entries.size() != 1) throw new IllegalArgumentException("duplicate catalog query parameter");
            values.put(key, entries.getFirst());
        });
        return values;
    }
}
