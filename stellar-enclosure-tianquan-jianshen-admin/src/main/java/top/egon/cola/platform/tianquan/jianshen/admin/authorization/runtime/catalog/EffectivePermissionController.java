package top.egon.cola.platform.tianquan.jianshen.admin.authorization.runtime.catalog;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.core.Authentication;
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import top.egon.cola.component.common.core.pojo.ResultRecord;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.EffectivePermissionSnapshot;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.PermissionManifest;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.ResourceAccess;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.ResourceType;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.annotation.LocalizedText;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.annotation.PermissionMessage;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.annotation.PermissionResource;
import top.egon.cola.platform.tianquan.jianshen.starter.security.Rbac3UserDetails;
import top.egon.cola.platform.tianquan.shoubing.contract.IdentityPrincipal;
import top.egon.cola.platform.tianquan.shoubing.starter.security.VerifiedUserTokenCarrier;

/** Identity and scope come from the verified credential and the host's fixed binding. */
@RestController
@PermissionMessage(pageCode = "permission.runtime", key = "current", defaultLocale = "en",
        defaults = @LocalizedText(locale = "en", text = "Read my effective permissions"))
public class EffectivePermissionController {
    private final PermissionRuntimeProofService proofs;
    private final PermissionRuntimeSnapshotRepository snapshots;

    public EffectivePermissionController(PermissionRuntimeProofService proofs, PermissionRuntimeSnapshotRepository snapshots) {
        this.proofs = proofs;
        this.snapshots = snapshots;
    }

    @PermissionResource(key = "tianquan-jianshen.api.authorization.current", type = ResourceType.API,
            labelPage = "permission.runtime", labelKey = "current", access = ResourceAccess.PUBLIC,
            allowedPrincipals = PermissionManifest.PrincipalType.USER)
    @GetMapping("/api/v1/authorization/effective-permissions")
    public ResultRecord<EffectivePermissionSnapshot> current(Authentication authentication, HttpServletRequest request) {
        if (!request.getParameterMap().isEmpty()) throw new IllegalArgumentException("target query parameters are not accepted");
        if (authentication == null || !authentication.isAuthenticated()) {
            throw new AuthenticationCredentialsNotFoundException("USER_IDENTITY_REQUIRED");
        }
        Object principal = authentication.getPrincipal();
        IdentityPrincipal identity = principal instanceof Rbac3UserDetails details ? details.identity()
                : principal instanceof IdentityPrincipal user ? user : null;
        if (identity == null) throw new AuthenticationCredentialsNotFoundException("USER_IDENTITY_REQUIRED");
        return ResultRecord.success(snapshots.current(proofs.local(identity, VerifiedUserTokenCarrier.current(request))).permissionSnapshot());
    }
}
