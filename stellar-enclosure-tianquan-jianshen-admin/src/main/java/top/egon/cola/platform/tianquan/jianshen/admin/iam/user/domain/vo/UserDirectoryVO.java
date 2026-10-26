package top.egon.cola.platform.tianquan.jianshen.admin.iam.user.domain.vo;

import top.egon.cola.platform.tianquan.jianshen.contract.permission.annotation.PermissionResource;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.annotation.PermissionGroup;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.annotation.FieldPermissions;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.ResourceType;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.PermissionMode;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.PermissionManifest;

/**
 * RBAC directory view for the local authorization projection. Identity
 * profile data is owned by Tianquan-Shoubing and is intentionally absent from this view.
 */
public record UserDirectoryVO(
        @PermissionResource(key = "tianquan-jianshen.field.iam.user.domain.vo.UserDirectoryVO.userId", type = ResourceType.FIELD,
                labelPage = "tianquan-jianshen.permissions", labelKey = "field.userId")
        @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
                plainRead = @PermissionGroup(mode = PermissionMode.ANY, codes = {"system:user-status:manage", "system:user:manage", "system:user:read"}))
        String userId,
        @PermissionResource(key = "tianquan-jianshen.field.iam.user.domain.vo.UserDirectoryVO.identitySub", type = ResourceType.FIELD,
                labelPage = "tianquan-jianshen.permissions", labelKey = "field.identitySub")
        @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
                plainRead = @PermissionGroup(mode = PermissionMode.ANY, codes = {"system:user-status:manage", "system:user:manage", "system:user:read"}))
        String identitySub,
        @PermissionResource(key = "tianquan-jianshen.field.iam.user.domain.vo.UserDirectoryVO.status", type = ResourceType.FIELD,
                labelPage = "tianquan-jianshen.permissions", labelKey = "field.status")
        @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
                plainRead = @PermissionGroup(mode = PermissionMode.ANY, codes = {"system:user-status:manage", "system:user:manage", "system:user:read"}))
        String status,
        @PermissionResource(key = "tianquan-jianshen.field.iam.user.domain.vo.UserDirectoryVO.authVersion", type = ResourceType.FIELD,
                labelPage = "tianquan-jianshen.permissions", labelKey = "field.authVersion")
        @FieldPermissions(valueType = PermissionManifest.JsonFieldType.NUMBER,
                plainRead = @PermissionGroup(mode = PermissionMode.ANY, codes = {"system:user-status:manage", "system:user:manage", "system:user:read"}))
        long authVersion
) {
}
