package top.egon.cola.platform.tianquan.jianshen.admin.authorization.catalog.domain.dto;

import top.egon.cola.platform.tianquan.jianshen.contract.permission.annotation.PermissionResource;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.annotation.PermissionGroup;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.annotation.FieldPermissions;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.ResourceType;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.PermissionManifest;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.CatalogScope;

import java.util.Objects;

public record CatalogGovernanceCommandDTO(@PermissionResource(key = "tianquan-jianshen.field.authorization.catalog.domain.dto.CatalogGovernanceCommandDTO.target", type = ResourceType.FIELD,
                labelPage = "tianquan-jianshen.permissions", labelKey = "field.target")
        @FieldPermissions(valueType = PermissionManifest.JsonFieldType.OBJECT,
                write = @PermissionGroup(codes = {"system:permission-catalog:manage"}))
        CatalogScope target, @PermissionResource(key = "tianquan-jianshen.field.authorization.catalog.domain.dto.CatalogGovernanceCommandDTO.kind", type = ResourceType.FIELD,
                labelPage = "tianquan-jianshen.permissions", labelKey = "field.kind")
        @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
                write = @PermissionGroup(codes = {"system:permission-catalog:manage"}))
        Kind kind, @PermissionResource(key = "tianquan-jianshen.field.authorization.catalog.domain.dto.CatalogGovernanceCommandDTO.identityId", type = ResourceType.FIELD,
                labelPage = "tianquan-jianshen.permissions", labelKey = "field.identityId")
        @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
                write = @PermissionGroup(codes = {"system:permission-catalog:manage"}))
        String identityId, @PermissionResource(key = "tianquan-jianshen.field.authorization.catalog.domain.dto.CatalogGovernanceCommandDTO.action", type = ResourceType.FIELD,
                labelPage = "tianquan-jianshen.permissions", labelKey = "field.action")
        @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
                write = @PermissionGroup(codes = {"system:permission-catalog:manage"}))
        Action action,
                                          @PermissionResource(key = "tianquan-jianshen.field.authorization.catalog.domain.dto.CatalogGovernanceCommandDTO.expectedVersion", type = ResourceType.FIELD,
                                                  labelPage = "tianquan-jianshen.permissions", labelKey = "field.expectedVersion")
                                          @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
                                                  write = @PermissionGroup(codes = {"system:permission-catalog:manage"}))
                                          String expectedVersion, @PermissionResource(key = "tianquan-jianshen.field.authorization.catalog.domain.dto.CatalogGovernanceCommandDTO.targetProducerId", type = ResourceType.FIELD,
                labelPage = "tianquan-jianshen.permissions", labelKey = "field.targetProducerId")
        @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
                write = @PermissionGroup(codes = {"system:permission-catalog:manage"}))
        String targetProducerId) {
    public enum Kind { RESOURCE, PERMISSION }
    public enum Action { DISABLE, RETIRE, TRANSFER }

    public CatalogGovernanceCommandDTO {
        Objects.requireNonNull(target, "target");
        Objects.requireNonNull(kind, "kind");
        Objects.requireNonNull(action, "action");
        decimal(identityId, false);
        decimal(expectedVersion, true);
        if (action == Action.TRANSFER) {
            if (targetProducerId == null || !targetProducerId.matches("[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}")) {
                throw new IllegalArgumentException("invalid target producer");
            }
        } else if (targetProducerId != null) throw new IllegalArgumentException("only an ownership transfer accepts targetProducerId");
    }

    public static long decimal(String value, boolean zero) {
        if (value == null || !value.matches(zero ? "0|[1-9][0-9]{0,18}" : "[1-9][0-9]{0,18}")) {
            throw new IllegalArgumentException("invalid catalog identity or version");
        }
        return Long.parseLong(value);
    }
}
