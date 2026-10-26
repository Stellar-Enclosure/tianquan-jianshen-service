package top.egon.cola.platform.tianquan.jianshen.admin.authorization.grant.business.domain.vo;

import top.egon.cola.platform.tianquan.jianshen.contract.permission.annotation.PermissionResource;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.annotation.PermissionGroup;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.annotation.FieldPermissions;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.ResourceType;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.PermissionMode;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.PermissionManifest;

import java.time.Instant;

/** User Business authorization fact enriched with current Tianshu display fields. */
public record UserBusinessAccessVO(
        @PermissionResource(key = "tianquan-jianshen.field.authorization.grant.business.domain.vo.UserBusinessAccessVO.accessId", type = ResourceType.FIELD,
                labelPage = "tianquan-jianshen.permissions", labelKey = "field.accessId")
        @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
                plainRead = @PermissionGroup(mode = PermissionMode.ANY, codes = {"system:user-business-access:manage", "system:user-business-access:read"}))
        String accessId,
        @PermissionResource(key = "tianquan-jianshen.field.authorization.grant.business.domain.vo.UserBusinessAccessVO.userId", type = ResourceType.FIELD,
                labelPage = "tianquan-jianshen.permissions", labelKey = "field.userId")
        @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
                plainRead = @PermissionGroup(mode = PermissionMode.ANY, codes = {"system:user-business-access:manage", "system:user-business-access:read"}))
        String userId,
        @PermissionResource(key = "tianquan-jianshen.field.authorization.grant.business.domain.vo.UserBusinessAccessVO.ddcBusinessId", type = ResourceType.FIELD,
                labelPage = "tianquan-jianshen.permissions", labelKey = "field.ddcBusinessId")
        @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
                plainRead = @PermissionGroup(mode = PermissionMode.ANY, codes = {"system:user-business-access:manage", "system:user-business-access:read"}))
        String ddcBusinessId,
        @PermissionResource(key = "tianquan-jianshen.field.authorization.grant.business.domain.vo.UserBusinessAccessVO.bizCode", type = ResourceType.FIELD,
                labelPage = "tianquan-jianshen.permissions", labelKey = "field.bizCode")
        @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
                plainRead = @PermissionGroup(mode = PermissionMode.ANY, codes = {"system:user-business-access:manage", "system:user-business-access:read"}))
        String bizCode,
        @PermissionResource(key = "tianquan-jianshen.field.authorization.grant.business.domain.vo.UserBusinessAccessVO.bizName", type = ResourceType.FIELD,
                labelPage = "tianquan-jianshen.permissions", labelKey = "field.bizName")
        @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
                plainRead = @PermissionGroup(mode = PermissionMode.ANY, codes = {"system:user-business-access:manage", "system:user-business-access:read"}))
        String bizName,
        @PermissionResource(key = "tianquan-jianshen.field.authorization.grant.business.domain.vo.UserBusinessAccessVO.status", type = ResourceType.FIELD,
                labelPage = "tianquan-jianshen.permissions", labelKey = "field.status")
        @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
                plainRead = @PermissionGroup(mode = PermissionMode.ANY, codes = {"system:user-business-access:manage", "system:user-business-access:read"}))
        String status,
        @PermissionResource(key = "tianquan-jianshen.field.authorization.grant.business.domain.vo.UserBusinessAccessVO.validFrom", type = ResourceType.FIELD,
                labelPage = "tianquan-jianshen.permissions", labelKey = "field.validFrom")
        @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
                plainRead = @PermissionGroup(mode = PermissionMode.ANY, codes = {"system:user-business-access:manage", "system:user-business-access:read"}))
        @com.fasterxml.jackson.annotation.JsonFormat(shape = com.fasterxml.jackson.annotation.JsonFormat.Shape.STRING)
        Instant validFrom,
        @PermissionResource(key = "tianquan-jianshen.field.authorization.grant.business.domain.vo.UserBusinessAccessVO.validTo", type = ResourceType.FIELD,
                labelPage = "tianquan-jianshen.permissions", labelKey = "field.validTo")
        @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
                plainRead = @PermissionGroup(mode = PermissionMode.ANY, codes = {"system:user-business-access:manage", "system:user-business-access:read"}))
        @com.fasterxml.jackson.annotation.JsonFormat(shape = com.fasterxml.jackson.annotation.JsonFormat.Shape.STRING)
        Instant validTo,
        @PermissionResource(key = "tianquan-jianshen.field.authorization.grant.business.domain.vo.UserBusinessAccessVO.sourceType", type = ResourceType.FIELD,
                labelPage = "tianquan-jianshen.permissions", labelKey = "field.sourceType")
        @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
                plainRead = @PermissionGroup(mode = PermissionMode.ANY, codes = {"system:user-business-access:manage", "system:user-business-access:read"}))
        String sourceType,
        @PermissionResource(key = "tianquan-jianshen.field.authorization.grant.business.domain.vo.UserBusinessAccessVO.sourceId", type = ResourceType.FIELD,
                labelPage = "tianquan-jianshen.permissions", labelKey = "field.sourceId")
        @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
                plainRead = @PermissionGroup(mode = PermissionMode.ANY, codes = {"system:user-business-access:manage", "system:user-business-access:read"}))
        String sourceId,
        @PermissionResource(key = "tianquan-jianshen.field.authorization.grant.business.domain.vo.UserBusinessAccessVO.reason", type = ResourceType.FIELD,
                labelPage = "tianquan-jianshen.permissions", labelKey = "field.reason")
        @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
                plainRead = @PermissionGroup(mode = PermissionMode.ANY, codes = {"system:user-business-access:manage", "system:user-business-access:read"}))
        String reason,
        @PermissionResource(key = "tianquan-jianshen.field.authorization.grant.business.domain.vo.UserBusinessAccessVO.ticketNo", type = ResourceType.FIELD,
                labelPage = "tianquan-jianshen.permissions", labelKey = "field.ticketNo")
        @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
                plainRead = @PermissionGroup(mode = PermissionMode.ANY, codes = {"system:user-business-access:manage", "system:user-business-access:read"}))
        String ticketNo,
        @PermissionResource(key = "tianquan-jianshen.field.authorization.grant.business.domain.vo.UserBusinessAccessVO.version", type = ResourceType.FIELD,
                labelPage = "tianquan-jianshen.permissions", labelKey = "field.version")
        @FieldPermissions(valueType = PermissionManifest.JsonFieldType.NUMBER,
                plainRead = @PermissionGroup(mode = PermissionMode.ANY, codes = {"system:user-business-access:manage", "system:user-business-access:read"}))
        long version) {
}
