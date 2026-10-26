package top.egon.cola.platform.tianquan.jianshen.admin.registration.catalog.domain.vo;

import top.egon.cola.platform.tianquan.jianshen.contract.permission.annotation.PermissionResource;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.ResourceAccess;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.ResourceType;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.PermissionManifest;

/** Immutable catalog transport value; persistence and orchestration stay outside this package. */
public record DeploymentQualificationReceiptVO(@PermissionResource(key = "tianquan-jianshen.field.registration.catalog.domain.vo.DeploymentQualificationReceiptVO.qualificationId", type = ResourceType.FIELD,
                labelPage = "tianquan-jianshen.permissions", labelKey = "field.qualificationId", access = ResourceAccess.PUBLIC,
                allowedPrincipals = {PermissionManifest.PrincipalType.SERVICE}, oauthScopes = {"tianquan-jianshen:permission-catalog:qualify"})
        String qualificationId, @PermissionResource(key = "tianquan-jianshen.field.registration.catalog.domain.vo.DeploymentQualificationReceiptVO.requestDigest", type = ResourceType.FIELD,
                labelPage = "tianquan-jianshen.permissions", labelKey = "field.requestDigest", access = ResourceAccess.PUBLIC,
                allowedPrincipals = {PermissionManifest.PrincipalType.SERVICE}, oauthScopes = {"tianquan-jianshen:permission-catalog:qualify"})
        String requestDigest,
        @PermissionResource(key = "tianquan-jianshen.field.registration.catalog.domain.vo.DeploymentQualificationReceiptVO.attestation", type = ResourceType.FIELD,
                labelPage = "tianquan-jianshen.permissions", labelKey = "field.attestation", access = ResourceAccess.PUBLIC,
                allowedPrincipals = {PermissionManifest.PrincipalType.SERVICE}, oauthScopes = {"tianquan-jianshen:permission-catalog:qualify"})
        top.egon.cola.platform.tianquan.jianshen.contract.permission.DeploymentQualificationRequest attestation,
        @PermissionResource(key = "tianquan-jianshen.field.registration.catalog.domain.vo.DeploymentQualificationReceiptVO.issuer", type = ResourceType.FIELD,
                labelPage = "tianquan-jianshen.permissions", labelKey = "field.issuer", access = ResourceAccess.PUBLIC,
                allowedPrincipals = {PermissionManifest.PrincipalType.SERVICE}, oauthScopes = {"tianquan-jianshen:permission-catalog:qualify"})
        String issuer, @PermissionResource(key = "tianquan-jianshen.field.registration.catalog.domain.vo.DeploymentQualificationReceiptVO.clientId", type = ResourceType.FIELD,
                labelPage = "tianquan-jianshen.permissions", labelKey = "field.clientId", access = ResourceAccess.PUBLIC,
                allowedPrincipals = {PermissionManifest.PrincipalType.SERVICE}, oauthScopes = {"tianquan-jianshen:permission-catalog:qualify"})
        String clientId, @PermissionResource(key = "tianquan-jianshen.field.registration.catalog.domain.vo.DeploymentQualificationReceiptVO.resourceUri", type = ResourceType.FIELD,
                labelPage = "tianquan-jianshen.permissions", labelKey = "field.resourceUri", access = ResourceAccess.PUBLIC,
                allowedPrincipals = {PermissionManifest.PrincipalType.SERVICE}, oauthScopes = {"tianquan-jianshen:permission-catalog:qualify"})
        String resourceUri,
        @PermissionResource(key = "tianquan-jianshen.field.registration.catalog.domain.vo.DeploymentQualificationReceiptVO.verifiedAt", type = ResourceType.FIELD,
                labelPage = "tianquan-jianshen.permissions", labelKey = "field.verifiedAt", access = ResourceAccess.PUBLIC,
                allowedPrincipals = {PermissionManifest.PrincipalType.SERVICE}, oauthScopes = {"tianquan-jianshen:permission-catalog:qualify"})
        @com.fasterxml.jackson.annotation.JsonFormat(shape=com.fasterxml.jackson.annotation.JsonFormat.Shape.STRING) java.time.Instant verifiedAt,
        @PermissionResource(key = "tianquan-jianshen.field.registration.catalog.domain.vo.DeploymentQualificationReceiptVO.expiresAt", type = ResourceType.FIELD,
                labelPage = "tianquan-jianshen.permissions", labelKey = "field.expiresAt", access = ResourceAccess.PUBLIC,
                allowedPrincipals = {PermissionManifest.PrincipalType.SERVICE}, oauthScopes = {"tianquan-jianshen:permission-catalog:qualify"})
        @com.fasterxml.jackson.annotation.JsonFormat(shape=com.fasterxml.jackson.annotation.JsonFormat.Shape.STRING) java.time.Instant expiresAt) { }
