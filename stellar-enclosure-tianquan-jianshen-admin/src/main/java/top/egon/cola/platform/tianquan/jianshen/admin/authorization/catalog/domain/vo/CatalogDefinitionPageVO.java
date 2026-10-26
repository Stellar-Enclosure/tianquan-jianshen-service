package top.egon.cola.platform.tianquan.jianshen.admin.authorization.catalog.domain.vo;

import top.egon.cola.platform.tianquan.jianshen.contract.permission.annotation.PermissionResource;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.annotation.PermissionGroup;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.annotation.FieldPermissions;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.ResourceType;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.PermissionManifest;

/** Immutable catalog transport value; persistence and orchestration stay outside this package. */
public record CatalogDefinitionPageVO(@PermissionResource(key = "tianquan-jianshen.field.authorization.catalog.domain.vo.CatalogDefinitionPageVO.target", type = ResourceType.FIELD,
                labelPage = "tianquan-jianshen.permissions", labelKey = "field.target")
        @FieldPermissions(valueType = PermissionManifest.JsonFieldType.OBJECT,
                plainRead = @PermissionGroup(codes = {"system:permission-catalog:read"}))
        top.egon.cola.platform.tianquan.jianshen.contract.permission.CatalogScope target,
        @PermissionResource(key = "tianquan-jianshen.field.authorization.catalog.domain.vo.CatalogDefinitionPageVO.kind", type = ResourceType.FIELD,
                labelPage = "tianquan-jianshen.permissions", labelKey = "field.kind")
        @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
                plainRead = @PermissionGroup(codes = {"system:permission-catalog:read"}))
        top.egon.cola.platform.tianquan.jianshen.admin.authorization.catalog.domain.dto.CatalogGovernanceCommandDTO.Kind kind,
        @PermissionResource(key = "tianquan-jianshen.field.authorization.catalog.domain.vo.CatalogDefinitionPageVO.definitions", type = ResourceType.FIELD,
                labelPage = "tianquan-jianshen.permissions", labelKey = "field.definitions")
        @FieldPermissions(valueType = PermissionManifest.JsonFieldType.ARRAY,
                plainRead = @PermissionGroup(codes = {"system:permission-catalog:read"}))
        java.util.List<CatalogDefinitionVO> definitions, @PermissionResource(key = "tianquan-jianshen.field.authorization.catalog.domain.vo.CatalogDefinitionPageVO.nextAfterId", type = ResourceType.FIELD,
                labelPage = "tianquan-jianshen.permissions", labelKey = "field.nextAfterId")
        @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
                plainRead = @PermissionGroup(codes = {"system:permission-catalog:read"}))
        String nextAfterId) {
    public CatalogDefinitionPageVO { definitions = java.util.List.copyOf(definitions); }
}
