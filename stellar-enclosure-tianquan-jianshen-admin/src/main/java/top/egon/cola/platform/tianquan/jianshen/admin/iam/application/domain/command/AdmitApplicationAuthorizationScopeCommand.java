package top.egon.cola.platform.tianquan.jianshen.admin.iam.application.domain.command;

import top.egon.cola.platform.tianquan.jianshen.contract.permission.annotation.PermissionResource;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.annotation.PermissionGroup;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.annotation.FieldPermissions;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.ResourceType;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.PermissionManifest;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.PositiveOrZero;

/** Request to admit a Tianshu Application as a tenant-local RBAC authorization scope. */
public record AdmitApplicationAuthorizationScopeCommand(
        @PermissionResource(key = "tianquan-jianshen.field.iam.application.domain.command.AdmitApplicationAuthorizationScopeCommand.ddcApplicationId", type = ResourceType.FIELD,
                labelPage = "tianquan-jianshen.permissions", labelKey = "field.ddcApplicationId")
        @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
                write = @PermissionGroup(codes = {"system:application:manage"}))
        @NotBlank String ddcApplicationId,
        @PermissionResource(key = "tianquan-jianshen.field.iam.application.domain.command.AdmitApplicationAuthorizationScopeCommand.displayPriority", type = ResourceType.FIELD,
                labelPage = "tianquan-jianshen.permissions", labelKey = "field.displayPriority")
        @FieldPermissions(valueType = PermissionManifest.JsonFieldType.NUMBER,
                write = @PermissionGroup(codes = {"system:application:manage"}))
        @PositiveOrZero int displayPriority) {
}
