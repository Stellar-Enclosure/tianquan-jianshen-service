package top.egon.cola.platform.tianquan.jianshen.admin.authorization.grant.rolepermission.domain.vo;

import top.egon.cola.platform.tianquan.jianshen.contract.permission.annotation.PermissionResource;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.annotation.PermissionGroup;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.annotation.FieldPermissions;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.ResourceType;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.PermissionManifest;

/** Immutable catalog transport value; persistence and orchestration stay outside this package. */
public record RolePermissionGrantViewVO(@PermissionResource(key = "tianquan-jianshen.field.authorization.grant.rolepermission.domain.vo.RolePermissionGrantViewVO.target", type = ResourceType.FIELD,
                labelPage = "tianquan-jianshen.permissions", labelKey = "field.target")
        @FieldPermissions(valueType = PermissionManifest.JsonFieldType.OBJECT,
                plainRead = @PermissionGroup(codes = {"system:role-permission:read"}))
        top.egon.cola.platform.tianquan.jianshen.contract.permission.CatalogScope target,
        @PermissionResource(key = "tianquan-jianshen.field.authorization.grant.rolepermission.domain.vo.RolePermissionGrantViewVO.roleId", type = ResourceType.FIELD,
                labelPage = "tianquan-jianshen.permissions", labelKey = "field.roleId")
        @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
                plainRead = @PermissionGroup(codes = {"system:role-permission:read"}))
        String roleId, @PermissionResource(key = "tianquan-jianshen.field.authorization.grant.rolepermission.domain.vo.RolePermissionGrantViewVO.version", type = ResourceType.FIELD,
                labelPage = "tianquan-jianshen.permissions", labelKey = "field.version")
        @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
                plainRead = @PermissionGroup(codes = {"system:role-permission:read"}))
        String version, @PermissionResource(key = "tianquan-jianshen.field.authorization.grant.rolepermission.domain.vo.RolePermissionGrantViewVO.catalogVersion", type = ResourceType.FIELD,
                labelPage = "tianquan-jianshen.permissions", labelKey = "field.catalogVersion")
        @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
                plainRead = @PermissionGroup(codes = {"system:role-permission:read"}))
        String catalogVersion, @PermissionResource(key = "tianquan-jianshen.field.authorization.grant.rolepermission.domain.vo.RolePermissionGrantViewVO.permissions", type = ResourceType.FIELD,
                labelPage = "tianquan-jianshen.permissions", labelKey = "field.permissions")
        @FieldPermissions(valueType = PermissionManifest.JsonFieldType.ARRAY,
                plainRead = @PermissionGroup(codes = {"system:role-permission:read"}))
        java.util.List<Grant> permissions) {
    public RolePermissionGrantViewVO { permissions = java.util.List.copyOf(permissions); }
    public record Grant(@PermissionResource(key = "tianquan-jianshen.field.authorization.grant.rolepermission.domain.vo.RolePermissionGrantViewVO.Grant.permissionCode", type = ResourceType.FIELD,
                labelPage = "tianquan-jianshen.permissions", labelKey = "field.permissionCode")
        @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
                plainRead = @PermissionGroup(codes = {"system:role-permission:read"}))
        String permissionCode,
            @PermissionResource(key = "tianquan-jianshen.field.authorization.grant.rolepermission.domain.vo.RolePermissionGrantViewVO.Grant.validFrom", type = ResourceType.FIELD,
                    labelPage = "tianquan-jianshen.permissions", labelKey = "field.validFrom")
            @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
                    plainRead = @PermissionGroup(codes = {"system:role-permission:read"}))
            @com.fasterxml.jackson.annotation.JsonFormat(shape=com.fasterxml.jackson.annotation.JsonFormat.Shape.STRING) java.time.Instant validFrom,
            @PermissionResource(key = "tianquan-jianshen.field.authorization.grant.rolepermission.domain.vo.RolePermissionGrantViewVO.Grant.validTo", type = ResourceType.FIELD,
                    labelPage = "tianquan-jianshen.permissions", labelKey = "field.validTo")
            @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
                    plainRead = @PermissionGroup(codes = {"system:role-permission:read"}))
            @com.fasterxml.jackson.annotation.JsonFormat(shape=com.fasterxml.jackson.annotation.JsonFormat.Shape.STRING) java.time.Instant validTo) { }
}
