package top.egon.cola.platform.tianquan.jianshen.admin.iam.business.domain.vo;

import top.egon.cola.platform.tianquan.jianshen.contract.permission.annotation.PermissionResource;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.annotation.PermissionGroup;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.annotation.FieldPermissions;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.ResourceType;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.PermissionManifest;

/** Tianshu-owned Business catalog data projected into Tianquan-Jianshen. */
public record BusinessCatalogEntry(
        @PermissionResource(key = "tianquan-jianshen.field.iam.business.domain.vo.BusinessCatalogEntry.ddcBusinessId", type = ResourceType.FIELD,
                labelPage = "tianquan-jianshen.permissions", labelKey = "field.ddcBusinessId")
        @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
                plainRead = @PermissionGroup(codes = {"system:business:read"}))
        String ddcBusinessId,
        @PermissionResource(key = "tianquan-jianshen.field.iam.business.domain.vo.BusinessCatalogEntry.bizCode", type = ResourceType.FIELD,
                labelPage = "tianquan-jianshen.permissions", labelKey = "field.bizCode")
        @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
                plainRead = @PermissionGroup(codes = {"system:business:read"}))
        String bizCode,
        @PermissionResource(key = "tianquan-jianshen.field.iam.business.domain.vo.BusinessCatalogEntry.bizName", type = ResourceType.FIELD,
                labelPage = "tianquan-jianshen.permissions", labelKey = "field.bizName")
        @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
                plainRead = @PermissionGroup(codes = {"system:business:read"}))
        String bizName,
        @PermissionResource(key = "tianquan-jianshen.field.iam.business.domain.vo.BusinessCatalogEntry.enabled", type = ResourceType.FIELD,
                labelPage = "tianquan-jianshen.permissions", labelKey = "field.enabled")
        @FieldPermissions(valueType = PermissionManifest.JsonFieldType.BOOLEAN,
                plainRead = @PermissionGroup(codes = {"system:business:read"}))
        boolean enabled) {
}
