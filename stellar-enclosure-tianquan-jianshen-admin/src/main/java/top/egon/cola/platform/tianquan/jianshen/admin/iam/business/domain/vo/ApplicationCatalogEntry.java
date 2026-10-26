package top.egon.cola.platform.tianquan.jianshen.admin.iam.business.domain.vo;

import top.egon.cola.platform.tianquan.jianshen.contract.permission.annotation.PermissionResource;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.annotation.PermissionGroup;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.annotation.FieldPermissions;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.ResourceType;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.PermissionManifest;

/** Tianshu-owned Application catalog data, including parent Business state. */
public record ApplicationCatalogEntry(
        @PermissionResource(key = "tianquan-jianshen.field.iam.business.domain.vo.ApplicationCatalogEntry.ddcApplicationId", type = ResourceType.FIELD,
                labelPage = "tianquan-jianshen.permissions", labelKey = "field.ddcApplicationId")
        @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
                plainRead = @PermissionGroup(codes = {"system:application:read"}))
        String ddcApplicationId,
        @PermissionResource(key = "tianquan-jianshen.field.iam.business.domain.vo.ApplicationCatalogEntry.ddcBusinessId", type = ResourceType.FIELD,
                labelPage = "tianquan-jianshen.permissions", labelKey = "field.ddcBusinessId")
        @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
                plainRead = @PermissionGroup(codes = {"system:application:read"}))
        String ddcBusinessId,
        @PermissionResource(key = "tianquan-jianshen.field.iam.business.domain.vo.ApplicationCatalogEntry.bizCode", type = ResourceType.FIELD,
                labelPage = "tianquan-jianshen.permissions", labelKey = "field.bizCode")
        @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
                plainRead = @PermissionGroup(codes = {"system:application:read"}))
        String bizCode,
        @PermissionResource(key = "tianquan-jianshen.field.iam.business.domain.vo.ApplicationCatalogEntry.appCode", type = ResourceType.FIELD,
                labelPage = "tianquan-jianshen.permissions", labelKey = "field.appCode")
        @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
                plainRead = @PermissionGroup(codes = {"system:application:read"}))
        String appCode,
        @PermissionResource(key = "tianquan-jianshen.field.iam.business.domain.vo.ApplicationCatalogEntry.appName", type = ResourceType.FIELD,
                labelPage = "tianquan-jianshen.permissions", labelKey = "field.appName")
        @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
                plainRead = @PermissionGroup(codes = {"system:application:read"}))
        String appName,
        @PermissionResource(key = "tianquan-jianshen.field.iam.business.domain.vo.ApplicationCatalogEntry.applicationEnabled", type = ResourceType.FIELD,
                labelPage = "tianquan-jianshen.permissions", labelKey = "field.applicationEnabled")
        @FieldPermissions(valueType = PermissionManifest.JsonFieldType.BOOLEAN,
                plainRead = @PermissionGroup(codes = {"system:application:read"}))
        boolean applicationEnabled,
        @PermissionResource(key = "tianquan-jianshen.field.iam.business.domain.vo.ApplicationCatalogEntry.businessEnabled", type = ResourceType.FIELD,
                labelPage = "tianquan-jianshen.permissions", labelKey = "field.businessEnabled")
        @FieldPermissions(valueType = PermissionManifest.JsonFieldType.BOOLEAN,
                plainRead = @PermissionGroup(codes = {"system:application:read"}))
        boolean businessEnabled) {
}
