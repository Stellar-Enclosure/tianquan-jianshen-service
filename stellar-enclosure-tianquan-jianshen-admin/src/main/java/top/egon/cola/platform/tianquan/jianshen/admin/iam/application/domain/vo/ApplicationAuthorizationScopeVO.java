package top.egon.cola.platform.tianquan.jianshen.admin.iam.application.domain.vo;

import top.egon.cola.platform.tianquan.jianshen.contract.permission.annotation.PermissionResource;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.annotation.PermissionGroup;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.annotation.FieldPermissions;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.ResourceType;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.PermissionMode;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.PermissionManifest;

/** Tenant-local RBAC authorization scope backed by a Tianshu Application. */
public record ApplicationAuthorizationScopeVO(
        @PermissionResource(key = "tianquan-jianshen.field.iam.application.domain.vo.ApplicationAuthorizationScopeVO.applicationId", type = ResourceType.FIELD,
                labelPage = "tianquan-jianshen.permissions", labelKey = "field.applicationId")
        @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
                plainRead = @PermissionGroup(mode = PermissionMode.ANY, codes = {"system:application:manage", "system:application:read"}))
        String applicationId,
        @PermissionResource(key = "tianquan-jianshen.field.iam.application.domain.vo.ApplicationAuthorizationScopeVO.ddcBusinessId", type = ResourceType.FIELD,
                labelPage = "tianquan-jianshen.permissions", labelKey = "field.ddcBusinessId")
        @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
                plainRead = @PermissionGroup(mode = PermissionMode.ANY, codes = {"system:application:manage", "system:application:read"}))
        String ddcBusinessId,
        @PermissionResource(key = "tianquan-jianshen.field.iam.application.domain.vo.ApplicationAuthorizationScopeVO.ddcApplicationId", type = ResourceType.FIELD,
                labelPage = "tianquan-jianshen.permissions", labelKey = "field.ddcApplicationId")
        @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
                plainRead = @PermissionGroup(mode = PermissionMode.ANY, codes = {"system:application:manage", "system:application:read"}))
        String ddcApplicationId,
        @PermissionResource(key = "tianquan-jianshen.field.iam.application.domain.vo.ApplicationAuthorizationScopeVO.businessCode", type = ResourceType.FIELD,
                labelPage = "tianquan-jianshen.permissions", labelKey = "field.businessCode")
        @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
                plainRead = @PermissionGroup(mode = PermissionMode.ANY, codes = {"system:application:manage", "system:application:read"}))
        String businessCode,
        @PermissionResource(key = "tianquan-jianshen.field.iam.application.domain.vo.ApplicationAuthorizationScopeVO.applicationCode", type = ResourceType.FIELD,
                labelPage = "tianquan-jianshen.permissions", labelKey = "field.applicationCode")
        @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
                plainRead = @PermissionGroup(mode = PermissionMode.ANY, codes = {"system:application:manage", "system:application:read"}))
        String applicationCode,
        @PermissionResource(key = "tianquan-jianshen.field.iam.application.domain.vo.ApplicationAuthorizationScopeVO.applicationName", type = ResourceType.FIELD,
                labelPage = "tianquan-jianshen.permissions", labelKey = "field.applicationName")
        @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
                plainRead = @PermissionGroup(mode = PermissionMode.ANY, codes = {"system:application:manage", "system:application:read"}))
        String applicationName,
        @PermissionResource(key = "tianquan-jianshen.field.iam.application.domain.vo.ApplicationAuthorizationScopeVO.status", type = ResourceType.FIELD,
                labelPage = "tianquan-jianshen.permissions", labelKey = "field.status")
        @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
                plainRead = @PermissionGroup(mode = PermissionMode.ANY, codes = {"system:application:manage", "system:application:read"}))
        String status,
        @PermissionResource(key = "tianquan-jianshen.field.iam.application.domain.vo.ApplicationAuthorizationScopeVO.displayPriority", type = ResourceType.FIELD,
                labelPage = "tianquan-jianshen.permissions", labelKey = "field.displayPriority")
        @FieldPermissions(valueType = PermissionManifest.JsonFieldType.NUMBER,
                plainRead = @PermissionGroup(mode = PermissionMode.ANY, codes = {"system:application:manage", "system:application:read"}))
        int displayPriority,
        @PermissionResource(key = "tianquan-jianshen.field.iam.application.domain.vo.ApplicationAuthorizationScopeVO.version", type = ResourceType.FIELD,
                labelPage = "tianquan-jianshen.permissions", labelKey = "field.version")
        @FieldPermissions(valueType = PermissionManifest.JsonFieldType.NUMBER,
                plainRead = @PermissionGroup(mode = PermissionMode.ANY, codes = {"system:application:manage", "system:application:read"}))
        long version) {
}
