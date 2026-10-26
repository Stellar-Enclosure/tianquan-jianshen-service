package top.egon.cola.platform.tianquan.jianshen.admin.authorization.runtime.decision.domain.dto;

import top.egon.cola.platform.tianquan.jianshen.contract.permission.annotation.PermissionResource;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.ResourceAccess;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.ResourceType;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.PermissionManifest;

import jakarta.validation.constraints.NotBlank;

/**
 * Transport request for checking a user's application entry permission.
 */
public record ResourceAccessDecisionRequestDTO(
        @PermissionResource(key = "tianquan-jianshen.field.authorization.runtime.decision.domain.dto.ResourceAccessDecisionRequestDTO.identitySub", type = ResourceType.FIELD,
                labelPage = "tianquan-jianshen.permissions", labelKey = "field.identitySub", access = ResourceAccess.PUBLIC,
                allowedPrincipals = {PermissionManifest.PrincipalType.SERVICE}, oauthScopes = {"service:authorization:decide"})
        @NotBlank String identitySub,
        @PermissionResource(key = "tianquan-jianshen.field.authorization.runtime.decision.domain.dto.ResourceAccessDecisionRequestDTO.tenantId", type = ResourceType.FIELD,
                labelPage = "tianquan-jianshen.permissions", labelKey = "field.tenantId", access = ResourceAccess.PUBLIC,
                allowedPrincipals = {PermissionManifest.PrincipalType.SERVICE}, oauthScopes = {"service:authorization:decide"})
        @NotBlank String tenantId,
        @PermissionResource(key = "tianquan-jianshen.field.authorization.runtime.decision.domain.dto.ResourceAccessDecisionRequestDTO.rbacApplicationCode", type = ResourceType.FIELD,
                labelPage = "tianquan-jianshen.permissions", labelKey = "field.rbacApplicationCode", access = ResourceAccess.PUBLIC,
                allowedPrincipals = {PermissionManifest.PrincipalType.SERVICE}, oauthScopes = {"service:authorization:decide"})
        @NotBlank String rbacApplicationCode,
        @PermissionResource(key = "tianquan-jianshen.field.authorization.runtime.decision.domain.dto.ResourceAccessDecisionRequestDTO.entryPermissionCode", type = ResourceType.FIELD,
                labelPage = "tianquan-jianshen.permissions", labelKey = "field.entryPermissionCode", access = ResourceAccess.PUBLIC,
                allowedPrincipals = {PermissionManifest.PrincipalType.SERVICE}, oauthScopes = {"service:authorization:decide"})
        @NotBlank String entryPermissionCode) {

    public ResourceAccessDecisionRequestDTO {
        identitySub = required(identitySub, "identitySub");
        tenantId = required(tenantId, "tenantId");
        rbacApplicationCode = required(rbacApplicationCode, "rbacApplicationCode");
        entryPermissionCode = required(entryPermissionCode, "entryPermissionCode");
    }

    public ResourceAccessRequestDTO toCommand() {
        return new ResourceAccessRequestDTO(
                identitySub, tenantId, rbacApplicationCode, entryPermissionCode);
    }

    private static String required(String value, String field) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(field + " is required");
        }
        return value.trim();
    }
}
