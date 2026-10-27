package top.egon.cola.platform.tianquan.jianshen.admin.authorization.grant.rolepermission.domain.dto;

import top.egon.cola.platform.tianquan.jianshen.admin.authorization.grant.rolepermission.domain.RolePermissionGrantCodes;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.annotation.PermissionResource;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.annotation.PermissionGroup;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.annotation.FieldPermissions;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.ResourceType;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.PermissionManifest;

import com.fasterxml.jackson.annotation.JsonFormat;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.CatalogScope;

import java.time.Instant;
import java.util.List;
import java.util.Objects;
import java.util.TreeSet;

/** Full replacement of this scope's direct permission-code grants, including scheduled grants. */
public record ReplaceRolePermissionsRequestDTO(@PermissionResource(key = "tianquan-jianshen.field.authorization.grant.rolepermission.domain.dto.ReplaceRolePermissionsRequestDTO.target", type = ResourceType.FIELD,
                labelPage = "tianquan-jianshen.permissions", labelKey = "field.target")
        @FieldPermissions(valueType = PermissionManifest.JsonFieldType.OBJECT,
                write = @PermissionGroup(codes = {RolePermissionGrantCodes.MANAGE}))
        CatalogScope target, @PermissionResource(key = "tianquan-jianshen.field.authorization.grant.rolepermission.domain.dto.ReplaceRolePermissionsRequestDTO.permissionCodes", type = ResourceType.FIELD,
                labelPage = "tianquan-jianshen.permissions", labelKey = "field.permissionCodes")
        @FieldPermissions(valueType = PermissionManifest.JsonFieldType.ARRAY,
                write = @PermissionGroup(codes = {RolePermissionGrantCodes.MANAGE}))
        List<String> permissionCodes, @PermissionResource(key = "tianquan-jianshen.field.authorization.grant.rolepermission.domain.dto.ReplaceRolePermissionsRequestDTO.expectedVersion", type = ResourceType.FIELD,
                labelPage = "tianquan-jianshen.permissions", labelKey = "field.expectedVersion")
        @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
                write = @PermissionGroup(codes = {RolePermissionGrantCodes.MANAGE}))
        String expectedVersion,
        @PermissionResource(key = "tianquan-jianshen.field.authorization.grant.rolepermission.domain.dto.ReplaceRolePermissionsRequestDTO.validFrom", type = ResourceType.FIELD,
                labelPage = "tianquan-jianshen.permissions", labelKey = "field.validFrom")
        @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
                write = @PermissionGroup(codes = {RolePermissionGrantCodes.MANAGE}))
        @JsonFormat(shape=JsonFormat.Shape.STRING) Instant validFrom, @PermissionResource(key = "tianquan-jianshen.field.authorization.grant.rolepermission.domain.dto.ReplaceRolePermissionsRequestDTO.validTo", type = ResourceType.FIELD,
                labelPage = "tianquan-jianshen.permissions", labelKey = "field.validTo")
        @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
                write = @PermissionGroup(codes = {RolePermissionGrantCodes.MANAGE}))
        @JsonFormat(shape=JsonFormat.Shape.STRING) Instant validTo) {
    public ReplaceRolePermissionsRequestDTO {
        Objects.requireNonNull(target, "target");
        if (permissionCodes == null || permissionCodes.size() > 10_000 || permissionCodes.stream().anyMatch(code ->
                code == null || !code.matches("[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}"))) throw new IllegalArgumentException("invalid permissionCodes");
        var unique = new TreeSet<>(permissionCodes);
        if (unique.size() != permissionCodes.size()) throw new IllegalArgumentException("duplicate permissionCodes");
        permissionCodes = List.copyOf(unique);
        if (expectedVersion == null || !expectedVersion.matches("0|[1-9][0-9]{0,18}") || Long.parseLong(expectedVersion) < 0) {
            throw new IllegalArgumentException("invalid expectedVersion");
        }
        if (validFrom != null && validTo != null && !validTo.isAfter(validFrom)) throw new IllegalArgumentException("invalid grant interval");
    }
}
