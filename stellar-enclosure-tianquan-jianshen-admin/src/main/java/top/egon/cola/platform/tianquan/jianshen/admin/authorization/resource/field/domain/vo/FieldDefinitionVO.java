package top.egon.cola.platform.tianquan.jianshen.admin.authorization.resource.field.domain.vo;

import top.egon.cola.platform.tianquan.jianshen.contract.permission.annotation.PermissionResource;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.annotation.PermissionGroup;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.annotation.FieldPermissions;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.ResourceType;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.PermissionManifest;

/** Global response field definition exposed by the IAM catalog. */
public record FieldDefinitionVO(
        @PermissionResource(key = "tianquan-jianshen.field.authorization.resource.field.domain.vo.FieldDefinitionVO.id", type = ResourceType.FIELD,
                labelPage = "tianquan-jianshen.permissions", labelKey = "field.id")
        @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
                plainRead = @PermissionGroup(codes = {"system:field-definition:read"}))
        String id,
        @PermissionResource(key = "tianquan-jianshen.field.authorization.resource.field.domain.vo.FieldDefinitionVO.applicationId", type = ResourceType.FIELD,
                labelPage = "tianquan-jianshen.permissions", labelKey = "field.applicationId")
        @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
                plainRead = @PermissionGroup(codes = {"system:field-definition:read"}))
        String applicationId,
        @PermissionResource(key = "tianquan-jianshen.field.authorization.resource.field.domain.vo.FieldDefinitionVO.resourceId", type = ResourceType.FIELD,
                labelPage = "tianquan-jianshen.permissions", labelKey = "field.resourceId")
        @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
                plainRead = @PermissionGroup(codes = {"system:field-definition:read"}))
        String resourceId,
        @PermissionResource(key = "tianquan-jianshen.field.authorization.resource.field.domain.vo.FieldDefinitionVO.fieldCode", type = ResourceType.FIELD,
                labelPage = "tianquan-jianshen.permissions", labelKey = "field.fieldCode")
        @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
                plainRead = @PermissionGroup(codes = {"system:field-definition:read"}))
        String fieldCode,
        @PermissionResource(key = "tianquan-jianshen.field.authorization.resource.field.domain.vo.FieldDefinitionVO.jsonPath", type = ResourceType.FIELD,
                labelPage = "tianquan-jianshen.permissions", labelKey = "field.jsonPath")
        @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
                plainRead = @PermissionGroup(codes = {"system:field-definition:read"}))
        String jsonPath,
        @PermissionResource(key = "tianquan-jianshen.field.authorization.resource.field.domain.vo.FieldDefinitionVO.dataType", type = ResourceType.FIELD,
                labelPage = "tianquan-jianshen.permissions", labelKey = "field.dataType")
        @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
                plainRead = @PermissionGroup(codes = {"system:field-definition:read"}))
        String dataType,
        @PermissionResource(key = "tianquan-jianshen.field.authorization.resource.field.domain.vo.FieldDefinitionVO.sensitivity", type = ResourceType.FIELD,
                labelPage = "tianquan-jianshen.permissions", labelKey = "field.sensitivity")
        @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
                plainRead = @PermissionGroup(codes = {"system:field-definition:read"}))
        String sensitivity,
        @PermissionResource(key = "tianquan-jianshen.field.authorization.resource.field.domain.vo.FieldDefinitionVO.defaultAccess", type = ResourceType.FIELD,
                labelPage = "tianquan-jianshen.permissions", labelKey = "field.defaultAccess")
        @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
                plainRead = @PermissionGroup(codes = {"system:field-definition:read"}))
        String defaultAccess,
        @PermissionResource(key = "tianquan-jianshen.field.authorization.resource.field.domain.vo.FieldDefinitionVO.maskingStrategy", type = ResourceType.FIELD,
                labelPage = "tianquan-jianshen.permissions", labelKey = "field.maskingStrategy")
        @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
                plainRead = @PermissionGroup(codes = {"system:field-definition:read"}))
        String maskingStrategy,
        @PermissionResource(key = "tianquan-jianshen.field.authorization.resource.field.domain.vo.FieldDefinitionVO.writable", type = ResourceType.FIELD,
                labelPage = "tianquan-jianshen.permissions", labelKey = "field.writable")
        @FieldPermissions(valueType = PermissionManifest.JsonFieldType.BOOLEAN,
                plainRead = @PermissionGroup(codes = {"system:field-definition:read"}))
        boolean writable,
        @PermissionResource(key = "tianquan-jianshen.field.authorization.resource.field.domain.vo.FieldDefinitionVO.exportable", type = ResourceType.FIELD,
                labelPage = "tianquan-jianshen.permissions", labelKey = "field.exportable")
        @FieldPermissions(valueType = PermissionManifest.JsonFieldType.BOOLEAN,
                plainRead = @PermissionGroup(codes = {"system:field-definition:read"}))
        boolean exportable,
        @PermissionResource(key = "tianquan-jianshen.field.authorization.resource.field.domain.vo.FieldDefinitionVO.status", type = ResourceType.FIELD,
                labelPage = "tianquan-jianshen.permissions", labelKey = "field.status")
        @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
                plainRead = @PermissionGroup(codes = {"system:field-definition:read"}))
        String status,
        @PermissionResource(key = "tianquan-jianshen.field.authorization.resource.field.domain.vo.FieldDefinitionVO.version", type = ResourceType.FIELD,
                labelPage = "tianquan-jianshen.permissions", labelKey = "field.version")
        @FieldPermissions(valueType = PermissionManifest.JsonFieldType.NUMBER,
                plainRead = @PermissionGroup(codes = {"system:field-definition:read"}))
        long version) {
}
