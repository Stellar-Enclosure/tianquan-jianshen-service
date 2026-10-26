package top.egon.cola.platform.tianquan.jianshen.admin.authorization.runtime.decision.domain.dto;

import top.egon.cola.platform.tianquan.jianshen.contract.permission.annotation.PermissionResource;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.ResourceAccess;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.ResourceType;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.PermissionManifest;

import jakarta.validation.constraints.NotBlank;

/**
 * Authorization-publication fence check bound to a user identity subject.
 */
public record AuthorizationFenceRequestDTO(@PermissionResource(key = "tianquan-jianshen.field.authorization.runtime.decision.domain.dto.AuthorizationFenceRequestDTO.identitySub", type = ResourceType.FIELD,
                labelPage = "tianquan-jianshen.permissions", labelKey = "field.identitySub", access = ResourceAccess.PUBLIC,
                allowedPrincipals = {PermissionManifest.PrincipalType.SERVICE}, oauthScopes = {"service:authorization:fence"})
        @NotBlank String identitySub) {

    public AuthorizationFenceRequestDTO {
        if (identitySub == null || identitySub.isBlank()) {
            throw new IllegalArgumentException("identitySub is required");
        }
        identitySub = identitySub.trim();
    }
}
