package top.egon.cola.platform.tianquan.jianshen.admin.authorization.runtime.decision.domain.vo;

import top.egon.cola.platform.tianquan.jianshen.contract.permission.annotation.PermissionResource;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.annotation.PermissionGroup;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.annotation.FieldPermissions;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.ResourceType;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.PermissionManifest;

/**
 * Authorization versions supplied by the caller and checked against the user snapshot.
 */
public record TokenVersionsVO(@PermissionResource(key = "tianquan-jianshen.field.authorization.runtime.decision.domain.vo.TokenVersionsVO.authVersion", type = ResourceType.FIELD,
                labelPage = "tianquan-jianshen.permissions", labelKey = "field.authVersion",
                allowedPrincipals = {PermissionManifest.PrincipalType.USER, PermissionManifest.PrincipalType.SERVICE}, oauthScopes = {"service:authorization:decide"})
        @FieldPermissions(valueType = PermissionManifest.JsonFieldType.NUMBER,
                write = @PermissionGroup(codes = {"system:authorization-simulation:execute"}))
        long authVersion, @PermissionResource(key = "tianquan-jianshen.field.authorization.runtime.decision.domain.vo.TokenVersionsVO.policyVersion", type = ResourceType.FIELD,
                labelPage = "tianquan-jianshen.permissions", labelKey = "field.policyVersion",
                allowedPrincipals = {PermissionManifest.PrincipalType.USER, PermissionManifest.PrincipalType.SERVICE}, oauthScopes = {"service:authorization:decide"})
        @FieldPermissions(valueType = PermissionManifest.JsonFieldType.NUMBER,
                write = @PermissionGroup(codes = {"system:authorization-simulation:execute"}))
        long policyVersion) {

    public TokenVersionsVO {
        if (authVersion < 0 || policyVersion < 0) {
            throw new IllegalArgumentException("authorization versions must not be negative");
        }
    }
}
