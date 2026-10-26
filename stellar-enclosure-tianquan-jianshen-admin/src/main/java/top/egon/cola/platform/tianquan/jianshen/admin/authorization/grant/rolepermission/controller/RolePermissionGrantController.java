package top.egon.cola.platform.tianquan.jianshen.admin.authorization.grant.rolepermission.controller;

import top.egon.cola.platform.tianquan.jianshen.starter.field.PermissionFieldBindingGuard;
import top.egon.cola.platform.tianquan.jianshen.starter.field.SubmittedFieldSet;

import top.egon.cola.component.yuheng.openapi.annotation.EgonApiCatalog;

import top.egon.cola.platform.tianquan.jianshen.admin.authorization.grant.rolepermission.domain.vo.RolePermissionGrantViewVO;
import io.swagger.v3.oas.annotations.Operation;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import top.egon.cola.component.common.core.pojo.ResultRecord;
import top.egon.cola.component.yuheng.openapi.annotation.EgonGatewayPolicy;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.grant.rolepermission.domain.dto.ReplaceRolePermissionsRequestDTO;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.grant.rolepermission.service.RolePermissionGrantService;
import top.egon.cola.platform.tianquan.jianshen.admin.registration.catalog.domain.convertor.PermissionCatalogJson;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.ResourceType;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.annotation.LocalizedText;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.annotation.PermissionDefinition;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.annotation.PermissionMessage;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.annotation.PermissionResource;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.annotation.RequiresPermissions;
import top.egon.cola.platform.tianquan.jianshen.starter.security.CurrentRbac3User;

import java.io.IOException;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

@RestController
@EgonApiCatalog(businessDomainCode = "xingyuan", businessDomainName = "平台治理域",
        entityDomainCode = "tianquan-jianshen", entityDomainName = "RBAC3权限实体域", interfaceGroupCode = "iam")
@RequestMapping("/api/v1/roles/{roleId}/permissions")
@PermissionDefinition(code=RolePermissionGrantService.READ, meaning="Read direct role permission grants in the managed tenant", labelPage="permission.role", labelKey="read")
@PermissionDefinition(code=RolePermissionGrantService.MANAGE, meaning="Replace direct role permission grants in the managed tenant", labelPage="permission.role", labelKey="manage")
@PermissionMessage(pageCode="permission.role", key="read", defaultLocale="en", defaults=@LocalizedText(locale="en", text="Read role permissions"))
@PermissionMessage(pageCode="permission.role", key="manage", defaultLocale="en", defaults=@LocalizedText(locale="en", text="Manage role permissions"))
public class RolePermissionGrantController {
    private final RolePermissionGrantService grants;
    private final PermissionCatalogJson json;

    private final PermissionFieldBindingGuard fieldWrites;

    public RolePermissionGrantController(RolePermissionGrantService grants, PermissionCatalogJson json, PermissionFieldBindingGuard fieldWrites) {
        this.fieldWrites = java.util.Objects.requireNonNull(fieldWrites, "fieldWrites");
        this.grants = grants;
        this.json = json;
    }

    @GetMapping(produces="application/json")
    @RequiresPermissions(codes=RolePermissionGrantService.READ)
    @PermissionResource(key="tianquan-jianshen.api.role.permissions.read", type=ResourceType.API, labelPage="permission.role", labelKey="read")
    @Operation(operationId="tianquan-jianshen-role-permissions-read-v1", summary="Read scoped role permission grants")
    @EgonGatewayPolicy(exposure=EgonGatewayPolicy.Exposure.EXTERNAL)
    public ResultRecord<RolePermissionGrantViewVO> read(@PathVariable String roleId, @RequestParam MultiValueMap<String, String> query) {
        var actor = new CurrentRbac3User().require();
        Map<String, Object> target = new LinkedHashMap<>();
        query.forEach((key, values) -> {
            if (values.size() != 1) throw new IllegalArgumentException("duplicate target query parameter");
            target.put(key, values.getFirst());
        });
        return ResultRecord.success(grants.read(json.scope(target), roleId, actor));
    }

    @PutMapping(consumes="application/json", produces="application/json")
    @RequiresPermissions(codes=RolePermissionGrantService.MANAGE)
    @PermissionResource(key="tianquan-jianshen.api.role.permissions.replace", type=ResourceType.API, labelPage="permission.role", labelKey="manage")
    @Operation(operationId="tianquan-jianshen-role-permissions-replace-v1", summary="Replace scoped permission-code grants atomically")
    @EgonGatewayPolicy(exposure=EgonGatewayPolicy.Exposure.EXTERNAL)
    public ResultRecord<RolePermissionGrantService.Result> replace(@PathVariable String roleId, HttpServletRequest request) throws IOException {
        var actor = new CurrentRbac3User().require();
        var body = json.readObject(request.getInputStream());
        if (!body.keySet().containsAll(Set.of("target", "permissionCodes", "expectedVersion"))
                || !Set.of("target", "permissionCodes", "expectedVersion", "validFrom", "validTo").containsAll(body.keySet())) {
            throw new IllegalArgumentException("invalid role permission request fields");
        }
        fieldWrites.require(ReplaceRolePermissionsRequestDTO.class, new SubmittedFieldSet(body.keySet()), Set.of("target", "permissionCodes", "expectedVersion", "validFrom", "validTo"));
        return ResultRecord.success(grants.replace(roleId, json.read(json.write(body), ReplaceRolePermissionsRequestDTO.class), actor));
    }
}
