package top.egon.cola.platform.tianquan.jianshen.admin.authorization.runtime.decision.controller;

import top.egon.cola.platform.tianquan.jianshen.contract.permission.annotation.PermissionResource;

import top.egon.cola.platform.tianquan.jianshen.contract.permission.ResourceAccess;

import top.egon.cola.platform.tianquan.jianshen.contract.permission.ResourceType;

import top.egon.cola.platform.tianquan.jianshen.contract.permission.PermissionManifest;

import jakarta.validation.Valid;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import top.egon.cola.component.common.core.pojo.ResultRecord;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import top.egon.cola.component.yuheng.openapi.annotation.EgonApiCatalog;
import top.egon.cola.component.yuheng.openapi.annotation.EgonGatewayPolicy;
import top.egon.cola.platform.tianquan.shoubing.contract.IdentityPrincipal;
import top.egon.cola.platform.tianquan.shoubing.contract.ServiceIdentityPrincipal;
import top.egon.cola.platform.tianquan.shoubing.starter.security.AccessTokenVerification;
import top.egon.cola.platform.tianquan.shoubing.starter.security.UserAccessTokenVerifier;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.runtime.decision.domain.dto.AuthorizationFenceRequestDTO;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.runtime.decision.domain.dto.DecisionRequestDTO;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.runtime.decision.domain.dto.ResourceAccessDecisionRequestDTO;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.runtime.decision.domain.dto.ResourceAccessRequestDTO;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.runtime.decision.domain.vo.DecisionBundleVO;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.runtime.decision.domain.vo.FenceVerificationVO;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.runtime.decision.domain.vo.ResourceAccessDecisionResponseVO;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.runtime.decision.service.AuthorizationDecisionService;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.runtime.service.SystemAuthorizationSnapshotService;
import top.egon.cola.platform.tianquan.jianshen.contract.authorization.SystemAuthorizationSnapshot;
import top.egon.cola.platform.tianquan.jianshen.core.rule.Rbac3RuleViolation;

import java.util.Objects;

/**
 * Internal RBAC authorization endpoints using a service token plus a verified USER token.
 */
@RestController
@RequestMapping("/internal/v1/authorization")
@Tag(name = "internal-authorization", description = "内部授权决策接口组")
@EgonApiCatalog(
        businessDomainCode = "xingyuan",
        businessDomainName = "平台治理域",
        entityDomainCode = "tianquan-jianshen",
        entityDomainName = "RBAC3权限实体域",
        interfaceGroupCode = "internal-authorization"
)
@top.egon.cola.platform.tianquan.jianshen.contract.permission.annotation.PermissionMessage(pageCode="permission.runtime", key="snapshot", defaultLocale="en", defaults=@top.egon.cola.platform.tianquan.jianshen.contract.permission.annotation.LocalizedText(locale="en", text="Read current user permission view"))
@top.egon.cola.platform.tianquan.jianshen.contract.permission.annotation.PermissionMessage(pageCode="permission.runtime", key="policy", defaultLocale="en", defaults=@top.egon.cola.platform.tianquan.jianshen.contract.permission.annotation.LocalizedText(locale="en", text="Read current service deployment policy"))
@top.egon.cola.platform.tianquan.jianshen.contract.permission.annotation.PermissionMessage(pageCode="permission.runtime", key="decision", defaultLocale="en", defaults=@top.egon.cola.platform.tianquan.jianshen.contract.permission.annotation.LocalizedText(locale="en", text="Evaluate current user permission decision"))
@top.egon.cola.platform.tianquan.jianshen.contract.permission.annotation.PermissionMessage(pageCode="permission.runtime", key="resourceAccess", defaultLocale="en", defaults=@top.egon.cola.platform.tianquan.jianshen.contract.permission.annotation.LocalizedText(locale="en", text="Evaluate current user application entry"))
@top.egon.cola.platform.tianquan.jianshen.contract.permission.annotation.PermissionMessage(pageCode="permission.runtime", key="fence", defaultLocale="en", defaults=@top.egon.cola.platform.tianquan.jianshen.contract.permission.annotation.LocalizedText(locale="en", text="Verify current user authorization fence"))
public class InternalAuthorizationController {

    private static final String SUBJECT_TOKEN_HEADER = "X-Egon-Subject-Token";

    private final AuthorizationDecisionService service;
    private final SystemAuthorizationSnapshotService systemSnapshots;
    private final UserAccessTokenVerifier userTokenVerifier;
    private final top.egon.cola.platform.tianquan.jianshen.admin.authorization.runtime.catalog.PermissionRuntimeProofService runtimeProofs;
    private final top.egon.cola.platform.tianquan.jianshen.admin.authorization.runtime.catalog.PermissionRuntimeSnapshotRepository runtimeSnapshots;


    @org.springframework.beans.factory.annotation.Autowired
    public InternalAuthorizationController(AuthorizationDecisionService service,
            SystemAuthorizationSnapshotService systemSnapshots, UserAccessTokenVerifier userTokenVerifier,
            top.egon.cola.platform.tianquan.jianshen.admin.authorization.runtime.catalog.PermissionRuntimeProofService runtimeProofs,
            top.egon.cola.platform.tianquan.jianshen.admin.authorization.runtime.catalog.PermissionRuntimeSnapshotRepository runtimeSnapshots) {
        this.service = Objects.requireNonNull(service, "service");
        this.systemSnapshots = Objects.requireNonNull(systemSnapshots, "systemSnapshots");
        this.userTokenVerifier = Objects.requireNonNull(userTokenVerifier, "userTokenVerifier");
        this.runtimeProofs = runtimeProofs;
        this.runtimeSnapshots = runtimeSnapshots;
    }

    public InternalAuthorizationController(AuthorizationDecisionService service,
            SystemAuthorizationSnapshotService systemSnapshots, UserAccessTokenVerifier userTokenVerifier) {
        this(service, systemSnapshots, userTokenVerifier, null, null);
    }

    @GetMapping("/policies/current")
    @top.egon.cola.platform.tianquan.jianshen.contract.permission.annotation.PermissionResource(
            key="tianquan-jianshen.api.runtime.servicePolicy", type=top.egon.cola.platform.tianquan.jianshen.contract.permission.ResourceType.API,
            labelPage="permission.runtime", labelKey="policy", allowedPrincipals=top.egon.cola.platform.tianquan.jianshen.contract.permission.PermissionManifest.PrincipalType.SERVICE,
            oauthScopes="service:authorization:policy")
    @top.egon.cola.platform.tianquan.shoubing.starter.security.RequiresServiceScope("service:authorization:policy")
    public ResultRecord<top.egon.cola.platform.tianquan.jianshen.contract.authorization.ServicePolicySnapshot> currentPolicy(
            @RequestParam String systemCode, @AuthenticationPrincipal ServiceIdentityPrincipal principal) {
        var authentication = org.springframework.security.core.context.SecurityContextHolder.getContext().getAuthentication();
        if (!(authentication instanceof top.egon.cola.platform.tianquan.shoubing.starter.security.IdpAuthenticationToken token)
                || token.getPrincipal() != principal || runtimeProofs == null || runtimeSnapshots == null) {
            throw new Rbac3RuleViolation("SERVICE_IDENTITY_DENIED");
        }
        var binding = runtimeProofs.policyBinding(principal, token.verifiedIssuer(), systemCode, "service:authorization:policy");
        return ResultRecord.success(runtimeSnapshots.policy(binding, principal.expiresAt()));
    }

    /**
     * Loads the current system snapshot for the verified USER subject.
     */
    @GetMapping("/snapshots/current")
    @top.egon.cola.platform.tianquan.jianshen.contract.permission.annotation.PermissionResource(
            key="tianquan-jianshen.api.runtime.userSnapshot", type=top.egon.cola.platform.tianquan.jianshen.contract.permission.ResourceType.API,
            labelPage="permission.runtime", labelKey="snapshot", allowedPrincipals=top.egon.cola.platform.tianquan.jianshen.contract.permission.PermissionManifest.PrincipalType.SERVICE,
            oauthScopes="service:authorization:snapshot")
    @top.egon.cola.platform.tianquan.shoubing.starter.security.RequiresServiceScope("service:authorization:snapshot")
    @Operation(
            operationId = "tianquan-jianshen-internal-system-snapshot-v2",
            summary = "按已验证用户身份读取系统授权快照",
            tags = {"tianquan-jianshen", "internal", "authorization"}
    )
    @EgonGatewayPolicy(
            exposure = EgonGatewayPolicy.Exposure.INTERNAL
    )
    public ResultRecord<SystemAuthorizationSnapshot> currentSnapshot(
            @RequestParam String systemCode,
            @RequestHeader(SUBJECT_TOKEN_HEADER) String userAccessToken,
            @AuthenticationPrincipal ServiceIdentityPrincipal servicePrincipal) {
        return ResultRecord.success(scoped(servicePrincipal, systemCode, userAccessToken, "service:authorization:snapshot"));
    }

    /** Executes a typed decision after binding the request to the verified USER subject. */
    @PostMapping("/decisions")
    @top.egon.cola.platform.tianquan.jianshen.contract.permission.annotation.PermissionResource(
            key="tianquan-jianshen.api.runtime.decision", type=top.egon.cola.platform.tianquan.jianshen.contract.permission.ResourceType.API,
            labelPage="permission.runtime", labelKey="decision", allowedPrincipals=top.egon.cola.platform.tianquan.jianshen.contract.permission.PermissionManifest.PrincipalType.SERVICE,
            oauthScopes="service:authorization:decide")
    @top.egon.cola.platform.tianquan.shoubing.starter.security.RequiresServiceScope("service:authorization:decide")
    @Operation(
            operationId = "tianquan-jianshen-internal-authorization-decision-v2",
            summary = "使用已验证用户身份执行类型化授权决策",
            tags = {"tianquan-jianshen", "internal", "authorization"}
    )
    @EgonGatewayPolicy(
            exposure = EgonGatewayPolicy.Exposure.INTERNAL
    )
    public ResultRecord<DecisionBundleVO> decide(
            @Valid @RequestBody DecisionRequestDTO request,
            @RequestHeader(SUBJECT_TOKEN_HEADER) String userAccessToken,
            @AuthenticationPrincipal ServiceIdentityPrincipal servicePrincipal) {
        var snapshot = scoped(servicePrincipal, request.resource().applicationCode(), userAccessToken, "service:authorization:decide");
        if (!snapshot.tenantId().equals(request.subject().tenantId()) || !snapshot.identitySub().equals(request.subject().identitySub())
                || !snapshot.rbac3UserId().equals(request.subject().userId()) || !snapshot.resourceCodes().contains(request.resource().resourceCode())) {
            throw new Rbac3RuleViolation("IDENTITY_SUBJECT_MISMATCH");
        }
        var app = new top.egon.cola.platform.tianquan.jianshen.contract.authorization.AppAuthorizationContext(
                snapshot.permissionSnapshot().catalogScope().catalogScopeId(), snapshot.systemCode(),
                snapshot.permissionSnapshot().activeRoleContext().rootRoleIds(), java.util.List.of(), snapshot.activeRoleIds(),
                snapshot.permissions(), snapshot.dataScopes(), snapshot.fieldPolicies(), snapshot.resourceCodes().stream().sorted().toList(), null);
        var userSnapshot = new top.egon.cola.platform.tianquan.jianshen.contract.authorization.UserAuthorizationSnapshot(
                snapshot.systemCode(), snapshot.tenantId(), snapshot.identitySub(), snapshot.rbac3UserId(), snapshot.authVersion(),
                snapshot.policyVersion(), java.util.List.of(app), snapshot.checksum(), snapshot.generatedAt(), snapshot.expiresAt());
        return ResultRecord.success(service.evaluateConsistentSnapshot(
                new top.egon.cola.platform.tianquan.jianshen.admin.authorization.runtime.decision.domain.vo.SnapshotRecordVO(
                        snapshot.tenantId(), snapshot.identitySub(), snapshot.rbac3UserId(), userSnapshot), request, java.util.Set.of(), java.util.Set.of()));
    }

    /** Decides whether the verified USER may enter an application. */
    @PostMapping("/resource-access-decisions")
    @top.egon.cola.platform.tianquan.jianshen.contract.permission.annotation.PermissionResource(
            key="tianquan-jianshen.api.runtime.resourceAccess", type=top.egon.cola.platform.tianquan.jianshen.contract.permission.ResourceType.API,
            labelPage="permission.runtime", labelKey="resourceAccess", allowedPrincipals=top.egon.cola.platform.tianquan.jianshen.contract.permission.PermissionManifest.PrincipalType.SERVICE,
            oauthScopes="service:authorization:decide")
    @top.egon.cola.platform.tianquan.shoubing.starter.security.RequiresServiceScope("service:authorization:decide")
    @Operation(
            operationId = "tianquan-jianshen-internal-resource-access-decision-v2",
            summary = "判定已验证用户是否具备应用入口权限",
            tags = {"tianquan-jianshen", "internal", "authorization"}
    )
    @EgonGatewayPolicy(
            exposure = EgonGatewayPolicy.Exposure.INTERNAL
    )
    public ResultRecord<ResourceAccessDecisionResponseVO> decideResourceAccess(
            @Valid @RequestBody ResourceAccessDecisionRequestDTO request,
            @RequestHeader(SUBJECT_TOKEN_HEADER) String userAccessToken,
            @AuthenticationPrincipal ServiceIdentityPrincipal servicePrincipal) {
        var snapshot = scoped(servicePrincipal, request.rbacApplicationCode(), userAccessToken, "service:authorization:decide");
        if (!snapshot.tenantId().equals(request.tenantId()) || !snapshot.identitySub().equals(request.identitySub())) {
            throw new Rbac3RuleViolation("IDENTITY_SUBJECT_MISMATCH");
        }
        boolean allowed = snapshot.permissions().contains(request.entryPermissionCode());
        return ResultRecord.success(new ResourceAccessDecisionResponseVO(
                allowed ? top.egon.cola.platform.tianquan.jianshen.contract.authorization.Decision.ALLOW
                        : top.egon.cola.platform.tianquan.jianshen.contract.authorization.Decision.DENY,
                allowed ? "ALLOW" : "ENTRY_PERMISSION_DENIED", snapshot.authVersion(), snapshot.policyVersion(), snapshot.generatedAt()));
    }

    /** Checks the user-scoped authorization publication fence. */
    @PostMapping("/fences/verify")
    @top.egon.cola.platform.tianquan.jianshen.contract.permission.annotation.PermissionResource(
            key="tianquan-jianshen.api.runtime.fence", type=top.egon.cola.platform.tianquan.jianshen.contract.permission.ResourceType.API,
            labelPage="permission.runtime", labelKey="fence", allowedPrincipals=top.egon.cola.platform.tianquan.jianshen.contract.permission.PermissionManifest.PrincipalType.SERVICE,
            oauthScopes="service:authorization:fence")
    @top.egon.cola.platform.tianquan.shoubing.starter.security.RequiresServiceScope("service:authorization:fence")
    @Operation(
            operationId = "tianquan-jianshen-internal-authorization-fence-verify-v2",
            summary = "校验用户授权传播 Fence",
            tags = {"tianquan-jianshen", "internal", "authorization"}
    )
    @EgonGatewayPolicy(
            exposure = EgonGatewayPolicy.Exposure.INTERNAL
    )
    public ResultRecord<FenceVerificationVO> verifyFence(
            @Valid @RequestBody AuthorizationFenceRequestDTO request,
            @RequestHeader(SUBJECT_TOKEN_HEADER) String userAccessToken,
            @AuthenticationPrincipal ServiceIdentityPrincipal servicePrincipal) {
        var snapshot = scoped(servicePrincipal, servicePrincipal.sourceAppCode(), userAccessToken, "service:authorization:fence");
        if (!snapshot.identitySub().equals(request.identitySub())) throw new Rbac3RuleViolation("IDENTITY_SUBJECT_MISMATCH");
        return ResultRecord.success(new FenceVerificationVO(
                top.egon.cola.platform.tianquan.jianshen.contract.authorization.Decision.ALLOW,
                "ALLOW", snapshot.identitySub(), snapshot.generatedAt()));
    }

    private SystemAuthorizationSnapshot scoped(ServiceIdentityPrincipal principal, String systemCode, String originalToken, String scope) {
        var authentication = org.springframework.security.core.context.SecurityContextHolder.getContext().getAuthentication();
        if (!(authentication instanceof top.egon.cola.platform.tianquan.shoubing.starter.security.IdpAuthenticationToken token)
                || token.getPrincipal() != principal || runtimeProofs == null || runtimeSnapshots == null) {
            throw new Rbac3RuleViolation("SERVICE_IDENTITY_DENIED");
        }
        return runtimeSnapshots.current(runtimeProofs.service(principal, token.verifiedIssuer(), systemCode, originalToken, scope));
    }
}
