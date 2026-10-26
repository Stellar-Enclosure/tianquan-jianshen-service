package top.egon.cola.platform.tianquan.jianshen.admin.authorization.catalog.domain.vo;

import top.egon.cola.platform.tianquan.jianshen.contract.permission.annotation.PermissionResource;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.annotation.PermissionGroup;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.annotation.FieldPermissions;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.ResourceType;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.PermissionManifest;

/** Immutable catalog transport value; persistence and orchestration stay outside this package. */
public record CatalogScopePageVO(@PermissionResource(key = "tianquan-jianshen.field.authorization.catalog.domain.vo.CatalogScopePageVO.scopes", type = ResourceType.FIELD,
                labelPage = "tianquan-jianshen.permissions", labelKey = "field.scopes")
        @FieldPermissions(valueType = PermissionManifest.JsonFieldType.ARRAY,
                plainRead = @PermissionGroup(codes = {"system:permission-catalog:read"}))
        java.util.List<Entry> scopes, @PermissionResource(key = "tianquan-jianshen.field.authorization.catalog.domain.vo.CatalogScopePageVO.nextAfterId", type = ResourceType.FIELD,
                labelPage = "tianquan-jianshen.permissions", labelKey = "field.nextAfterId")
        @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
                plainRead = @PermissionGroup(codes = {"system:permission-catalog:read"}))
        String nextAfterId) {
    public CatalogScopePageVO { scopes = java.util.List.copyOf(scopes); }
    public record Entry(@PermissionResource(key = "tianquan-jianshen.field.authorization.catalog.domain.vo.CatalogScopePageVO.Entry.scope", type = ResourceType.FIELD,
                labelPage = "tianquan-jianshen.permissions", labelKey = "field.scope")
        @FieldPermissions(valueType = PermissionManifest.JsonFieldType.OBJECT,
                plainRead = @PermissionGroup(codes = {"system:permission-catalog:read"}))
        top.egon.cola.platform.tianquan.jianshen.contract.permission.CatalogScope scope, @PermissionResource(key = "tianquan-jianshen.field.authorization.catalog.domain.vo.CatalogScopePageVO.Entry.applicationId", type = ResourceType.FIELD,
                labelPage = "tianquan-jianshen.permissions", labelKey = "field.applicationId")
        @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
                plainRead = @PermissionGroup(codes = {"system:permission-catalog:read"}))
        String applicationId, @PermissionResource(key = "tianquan-jianshen.field.authorization.catalog.domain.vo.CatalogScopePageVO.Entry.producerCount", type = ResourceType.FIELD,
                labelPage = "tianquan-jianshen.permissions", labelKey = "field.producerCount")
        @FieldPermissions(valueType = PermissionManifest.JsonFieldType.NUMBER,
                plainRead = @PermissionGroup(codes = {"system:permission-catalog:read"}))
        long producerCount) { }
}
