package top.egon.cola.platform.tianquan.jianshen.admin.iam.business.domain.vo;

import top.egon.cola.platform.tianquan.jianshen.contract.permission.annotation.PermissionResource;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.annotation.PermissionGroup;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.annotation.FieldPermissions;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.ResourceType;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.PermissionManifest;

import java.time.Instant;

/** Derived Application access; it is never persisted as UserApplicationAccess. */
public record UserApplicationAccessVO(
        @PermissionResource(key = "tianquan-jianshen.field.iam.business.domain.vo.UserApplicationAccessVO.applicationId", type = ResourceType.FIELD,
                labelPage = "tianquan-jianshen.permissions", labelKey = "field.applicationId")
        @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
                plainRead = @PermissionGroup(codes = {"system:user-application-access:read"}))
        String applicationId,
        @PermissionResource(key = "tianquan-jianshen.field.iam.business.domain.vo.UserApplicationAccessVO.ddcBusinessId", type = ResourceType.FIELD,
                labelPage = "tianquan-jianshen.permissions", labelKey = "field.ddcBusinessId")
        @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
                plainRead = @PermissionGroup(codes = {"system:user-application-access:read"}))
        String ddcBusinessId,
        @PermissionResource(key = "tianquan-jianshen.field.iam.business.domain.vo.UserApplicationAccessVO.ddcApplicationId", type = ResourceType.FIELD,
                labelPage = "tianquan-jianshen.permissions", labelKey = "field.ddcApplicationId")
        @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
                plainRead = @PermissionGroup(codes = {"system:user-application-access:read"}))
        String ddcApplicationId,
        @PermissionResource(key = "tianquan-jianshen.field.iam.business.domain.vo.UserApplicationAccessVO.businessCode", type = ResourceType.FIELD,
                labelPage = "tianquan-jianshen.permissions", labelKey = "field.businessCode")
        @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
                plainRead = @PermissionGroup(codes = {"system:user-application-access:read"}))
        String businessCode,
        @PermissionResource(key = "tianquan-jianshen.field.iam.business.domain.vo.UserApplicationAccessVO.applicationCode", type = ResourceType.FIELD,
                labelPage = "tianquan-jianshen.permissions", labelKey = "field.applicationCode")
        @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
                plainRead = @PermissionGroup(codes = {"system:user-application-access:read"}))
        String applicationCode,
        @PermissionResource(key = "tianquan-jianshen.field.iam.business.domain.vo.UserApplicationAccessVO.applicationName", type = ResourceType.FIELD,
                labelPage = "tianquan-jianshen.permissions", labelKey = "field.applicationName")
        @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
                plainRead = @PermissionGroup(codes = {"system:user-application-access:read"}))
        String applicationName,
        @PermissionResource(key = "tianquan-jianshen.field.iam.business.domain.vo.UserApplicationAccessVO.applicationStatus", type = ResourceType.FIELD,
                labelPage = "tianquan-jianshen.permissions", labelKey = "field.applicationStatus")
        @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
                plainRead = @PermissionGroup(codes = {"system:user-application-access:read"}))
        String applicationStatus,
        @PermissionResource(key = "tianquan-jianshen.field.iam.business.domain.vo.UserApplicationAccessVO.observedAt", type = ResourceType.FIELD,
                labelPage = "tianquan-jianshen.permissions", labelKey = "field.observedAt")
        @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
                plainRead = @PermissionGroup(codes = {"system:user-application-access:read"}))
        @com.fasterxml.jackson.annotation.JsonFormat(shape = com.fasterxml.jackson.annotation.JsonFormat.Shape.STRING)
        Instant observedAt) {
}
