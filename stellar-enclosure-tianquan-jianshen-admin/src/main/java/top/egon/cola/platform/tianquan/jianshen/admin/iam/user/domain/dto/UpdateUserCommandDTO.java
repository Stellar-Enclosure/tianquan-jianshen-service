package top.egon.cola.platform.tianquan.jianshen.admin.iam.user.domain.dto;

import top.egon.cola.platform.tianquan.jianshen.contract.permission.annotation.PermissionResource;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.annotation.PermissionGroup;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.annotation.FieldPermissions;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.ResourceType;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.PermissionManifest;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.PositiveOrZero;

/** Command for changing only the local Tianquan-Shoubing subject binding. */
public record UpdateUserCommandDTO(
        @PermissionResource(key = "tianquan-jianshen.field.iam.user.domain.dto.UpdateUserCommandDTO.identitySub", type = ResourceType.FIELD,
                labelPage = "tianquan-jianshen.permissions", labelKey = "field.identitySub")
        @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
                write = @PermissionGroup(codes = {"system:user:manage"}))
        @NotBlank String identitySub,
        @PermissionResource(key = "tianquan-jianshen.field.iam.user.domain.dto.UpdateUserCommandDTO.expectedAuthVersion", type = ResourceType.FIELD,
                labelPage = "tianquan-jianshen.permissions", labelKey = "field.expectedAuthVersion")
        @FieldPermissions(valueType = PermissionManifest.JsonFieldType.NUMBER,
                write = @PermissionGroup(codes = {"system:user:manage"}))
        @PositiveOrZero long expectedAuthVersion) {
}
