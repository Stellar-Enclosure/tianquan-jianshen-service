package top.egon.cola.platform.tianquan.jianshen.admin.iam.user.domain.dto;

import top.egon.cola.platform.tianquan.jianshen.contract.permission.annotation.PermissionResource;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.annotation.PermissionGroup;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.annotation.FieldPermissions;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.ResourceType;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.PermissionManifest;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import top.egon.cola.platform.tianquan.jianshen.admin.iam.user.domain.enums.UserStatusEnum;

/** Command for creating an RBAC membership bound to an Tianquan-Shoubing subject. */
public record CreateUserCommandDTO(
        @PermissionResource(key = "tianquan-jianshen.field.iam.user.domain.dto.CreateUserCommandDTO.identitySub", type = ResourceType.FIELD,
                labelPage = "tianquan-jianshen.permissions", labelKey = "field.identitySub")
        @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
                write = @PermissionGroup(codes = {"system:user:manage"}))
        @NotBlank String identitySub,
        @PermissionResource(key = "tianquan-jianshen.field.iam.user.domain.dto.CreateUserCommandDTO.status", type = ResourceType.FIELD,
                labelPage = "tianquan-jianshen.permissions", labelKey = "field.status")
        @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
                write = @PermissionGroup(codes = {"system:user:manage"}))
        @NotNull UserStatusEnum status) {
}
