package top.egon.cola.platform.tianquan.jianshen.admin.authorization.runtime.decision.domain.vo;

import top.egon.cola.platform.tianquan.jianshen.contract.permission.annotation.PermissionResource;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.ResourceAccess;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.ResourceType;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.PermissionManifest;

import top.egon.cola.platform.tianquan.jianshen.contract.authorization.Decision;

import java.time.Instant;
import java.util.Objects;

/**
 * Minimal application-entry decision without server-side identity state.
 */
public record ResourceAccessDecisionResponseVO(
        @PermissionResource(key = "tianquan-jianshen.field.authorization.runtime.decision.domain.vo.ResourceAccessDecisionResponseVO.decision", type = ResourceType.FIELD,
                labelPage = "tianquan-jianshen.permissions", labelKey = "field.decision", access = ResourceAccess.PUBLIC,
                allowedPrincipals = {PermissionManifest.PrincipalType.SERVICE}, oauthScopes = {"service:authorization:decide"})
        Decision decision,
        @PermissionResource(key = "tianquan-jianshen.field.authorization.runtime.decision.domain.vo.ResourceAccessDecisionResponseVO.reasonCode", type = ResourceType.FIELD,
                labelPage = "tianquan-jianshen.permissions", labelKey = "field.reasonCode", access = ResourceAccess.PUBLIC,
                allowedPrincipals = {PermissionManifest.PrincipalType.SERVICE}, oauthScopes = {"service:authorization:decide"})
        String reasonCode,
        @PermissionResource(key = "tianquan-jianshen.field.authorization.runtime.decision.domain.vo.ResourceAccessDecisionResponseVO.authVersion", type = ResourceType.FIELD,
                labelPage = "tianquan-jianshen.permissions", labelKey = "field.authVersion", access = ResourceAccess.PUBLIC,
                allowedPrincipals = {PermissionManifest.PrincipalType.SERVICE}, oauthScopes = {"service:authorization:decide"})
        Long authVersion,
        @PermissionResource(key = "tianquan-jianshen.field.authorization.runtime.decision.domain.vo.ResourceAccessDecisionResponseVO.policyVersion", type = ResourceType.FIELD,
                labelPage = "tianquan-jianshen.permissions", labelKey = "field.policyVersion", access = ResourceAccess.PUBLIC,
                allowedPrincipals = {PermissionManifest.PrincipalType.SERVICE}, oauthScopes = {"service:authorization:decide"})
        Long policyVersion,
        @PermissionResource(key = "tianquan-jianshen.field.authorization.runtime.decision.domain.vo.ResourceAccessDecisionResponseVO.decidedAt", type = ResourceType.FIELD,
                labelPage = "tianquan-jianshen.permissions", labelKey = "field.decidedAt", access = ResourceAccess.PUBLIC,
                allowedPrincipals = {PermissionManifest.PrincipalType.SERVICE}, oauthScopes = {"service:authorization:decide"})
        @com.fasterxml.jackson.annotation.JsonFormat(shape = com.fasterxml.jackson.annotation.JsonFormat.Shape.STRING)
        Instant decidedAt) {

    public ResourceAccessDecisionResponseVO {
        decision = Objects.requireNonNull(decision, "decision");
        reasonCode = required(reasonCode, "reasonCode");
        decidedAt = Objects.requireNonNull(decidedAt, "decidedAt");
        int versions = (authVersion == null ? 0 : 1) + (policyVersion == null ? 0 : 1);
        if (versions != 0 && versions != 2) {
            throw new IllegalArgumentException("authorization versions must be all present or absent");
        }
        if ((authVersion != null && authVersion < 0)
                || (policyVersion != null && policyVersion < 0)) {
            throw new IllegalArgumentException("authorization versions must not be negative");
        }
    }

    public static ResourceAccessDecisionResponseVO from(ResourceAccessDecisionVO result) {
        Objects.requireNonNull(result, "result");
        return new ResourceAccessDecisionResponseVO(
                result.decision(), result.reasonCode(), result.authVersion(),
                result.policyVersion(), result.decidedAt());
    }

    private static String required(String value, String field) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(field + " is required");
        }
        return value.trim();
    }
}
