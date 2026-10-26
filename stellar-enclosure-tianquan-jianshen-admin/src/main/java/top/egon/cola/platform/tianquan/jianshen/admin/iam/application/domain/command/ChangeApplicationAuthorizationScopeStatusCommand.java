package top.egon.cola.platform.tianquan.jianshen.admin.iam.application.domain.command;

import top.egon.cola.platform.tianquan.jianshen.contract.permission.annotation.PermissionResource;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.annotation.PermissionGroup;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.annotation.FieldPermissions;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.ResourceType;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.PermissionManifest;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.PositiveOrZero;

/** Optimistic-concurrency request to change a local Application scope status. */
public record ChangeApplicationAuthorizationScopeStatusCommand(
        @PermissionResource(key = "tianquan-jianshen.field.iam.application.domain.command.ChangeApplicationAuthorizationScopeStatusCommand.status", type = ResourceType.FIELD,
                labelPage = "tianquan-jianshen.permissions", labelKey = "field.status")
        @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
                write = @PermissionGroup(codes = {"system:application:manage"}))
        @NotBlank String status,
        @PermissionResource(key = "tianquan-jianshen.field.iam.application.domain.command.ChangeApplicationAuthorizationScopeStatusCommand.expectedVersion", type = ResourceType.FIELD,
                labelPage = "tianquan-jianshen.permissions", labelKey = "field.expectedVersion")
        @FieldPermissions(valueType = PermissionManifest.JsonFieldType.NUMBER,
                write = @PermissionGroup(codes = {"system:application:manage"}))
        @PositiveOrZero long expectedVersion) {
}
