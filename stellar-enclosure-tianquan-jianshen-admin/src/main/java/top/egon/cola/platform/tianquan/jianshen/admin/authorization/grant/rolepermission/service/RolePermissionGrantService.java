package top.egon.cola.platform.tianquan.jianshen.admin.authorization.grant.rolepermission.service;

import top.egon.cola.platform.tianquan.jianshen.contract.permission.annotation.PermissionResource;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.annotation.PermissionGroup;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.annotation.FieldPermissions;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.ResourceType;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.PermissionManifest;

import top.egon.cola.platform.tianquan.jianshen.admin.authorization.grant.rolepermission.domain.vo.RolePermissionGrantViewVO;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import top.egon.cola.platform.tianquan.jianshen.admin.audit.domain.dto.AuditCommandDTO;
import top.egon.cola.platform.tianquan.jianshen.admin.audit.service.AuditQueryService;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.grant.rolepermission.domain.dto.ReplaceRolePermissionsRequestDTO;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.grant.rolepermission.repository.RolePermissionGrantRepository;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.runtime.domain.vo.AuthorizationEventVO;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.runtime.repository.AuthorizationEventPublisher;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.runtime.state.repository.TenantAuthorizationStateRepository;
import top.egon.cola.platform.tianquan.jianshen.admin.registration.catalog.repository.CatalogAdministrationGuard;
import top.egon.cola.platform.tianquan.jianshen.admin.shared.domain.DatabaseClock;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.CatalogScope;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.ManifestRegistrationRequest;
import top.egon.cola.platform.tianquan.jianshen.starter.security.Rbac3UserDetails;

import java.util.List;
import java.util.Map;

@Service
public class RolePermissionGrantService {
    public static final String READ = "system:role-permission:read";
    public static final String MANAGE = "system:role-permission:manage";
    public record Result(@PermissionResource(key = "tianquan-jianshen.field.authorization.grant.rolepermission.service.RolePermissionGrantService.Result.target", type = ResourceType.FIELD,
                labelPage = "tianquan-jianshen.permissions", labelKey = "field.target")
        @FieldPermissions(valueType = PermissionManifest.JsonFieldType.OBJECT,
                plainRead = @PermissionGroup(codes = {"system:role-permission:manage"}))
        CatalogScope target, @PermissionResource(key = "tianquan-jianshen.field.authorization.grant.rolepermission.service.RolePermissionGrantService.Result.roleId", type = ResourceType.FIELD,
                labelPage = "tianquan-jianshen.permissions", labelKey = "field.roleId")
        @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
                plainRead = @PermissionGroup(codes = {"system:role-permission:manage"}))
        String roleId, @PermissionResource(key = "tianquan-jianshen.field.authorization.grant.rolepermission.service.RolePermissionGrantService.Result.version", type = ResourceType.FIELD,
                labelPage = "tianquan-jianshen.permissions", labelKey = "field.version")
        @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
                plainRead = @PermissionGroup(codes = {"system:role-permission:manage"}))
        String version, @PermissionResource(key = "tianquan-jianshen.field.authorization.grant.rolepermission.service.RolePermissionGrantService.Result.policyVersion", type = ResourceType.FIELD,
                labelPage = "tianquan-jianshen.permissions", labelKey = "field.policyVersion")
        @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
                plainRead = @PermissionGroup(codes = {"system:role-permission:manage"}))
        String policyVersion, @PermissionResource(key = "tianquan-jianshen.field.authorization.grant.rolepermission.service.RolePermissionGrantService.Result.permissionCodes", type = ResourceType.FIELD,
                labelPage = "tianquan-jianshen.permissions", labelKey = "field.permissionCodes")
        @FieldPermissions(valueType = PermissionManifest.JsonFieldType.ARRAY,
                plainRead = @PermissionGroup(codes = {"system:role-permission:manage"}))
        List<String> permissionCodes,
                         @PermissionResource(key = "tianquan-jianshen.field.authorization.grant.rolepermission.service.RolePermissionGrantService.Result.addedCount", type = ResourceType.FIELD,
                                 labelPage = "tianquan-jianshen.permissions", labelKey = "field.addedCount")
                         @FieldPermissions(valueType = PermissionManifest.JsonFieldType.NUMBER,
                                 plainRead = @PermissionGroup(codes = {"system:role-permission:manage"}))
                         long addedCount, @PermissionResource(key = "tianquan-jianshen.field.authorization.grant.rolepermission.service.RolePermissionGrantService.Result.removedCount", type = ResourceType.FIELD,
                labelPage = "tianquan-jianshen.permissions", labelKey = "field.removedCount")
        @FieldPermissions(valueType = PermissionManifest.JsonFieldType.NUMBER,
                plainRead = @PermissionGroup(codes = {"system:role-permission:manage"}))
        long removedCount) {
        public Result { permissionCodes = List.copyOf(permissionCodes); }
    }

    private final CatalogAdministrationGuard guard;
    private final RolePermissionGrantRepository grants;
    private final TenantAuthorizationStateRepository policy;
    private final AuthorizationEventPublisher events;
    private final AuditQueryService audit;
    private final DatabaseClock clock;

    public RolePermissionGrantService(CatalogAdministrationGuard guard, RolePermissionGrantRepository grants,
            TenantAuthorizationStateRepository policy, AuthorizationEventPublisher events, AuditQueryService audit, DatabaseClock clock) {
        this.guard = guard;
        this.grants = grants;
        this.policy = policy;
        this.events = events;
        this.audit = audit;
        this.clock = clock;
    }

    @Transactional
    public RolePermissionGrantViewVO read(CatalogScope target, String roleId, Rbac3UserDetails actor) {
        long role = role(roleId);
        var scope = guard.require(target, actor, READ, clock.transactionNow());
        return grants.read(scope, role);
    }

    @Transactional
    public Result replace(String roleId, ReplaceRolePermissionsRequestDTO request, Rbac3UserDetails actor) {
        long role = role(roleId);
        var now = clock.transactionNow();
        var scope = guard.require(request.target(), actor, MANAGE, now);
        var mutation = grants.replace(scope, role, request, actor.rbac3UserId(), now);
        long version = policy.increment(Long.parseLong(request.target().tenantId()), actor.rbac3UserId());
        String trace = request.target().catalogScopeId() + ':' + roleId + ':' + mutation.version();
        events.enqueue(new AuthorizationEventVO(request.target().tenantId(), "ROLE", roleId, "ROLE_PERMISSION_CHANGED",
                Map.of("catalogScopeId", request.target().catalogScopeId(), "roleId", roleId,
                        "permissionVersion", mutation.version(), "policyVersion", Long.toString(version)), trace));
        audit.record(new AuditCommandDTO(request.target().tenantId(), "ROLE_PERMISSION_REPLACED", "SUCCESS", "INFO", "USER",
                actor.rbac3UserId(), "ROLE", roleId, null, "ALLOW", trace, trace, Map.of(),
                Map.of("scope", ManifestRegistrationRequest.targetMap(request.target()), "permissionVersion", mutation.version(),
                        "policyVersion", Long.toString(version), "permissionCodesDigest", top.egon.cola.platform.tianquan.jianshen.contract.permission.CanonicalJson.digest(request.permissionCodes()),
                        "addedCount", mutation.addedCount(), "removedCount", mutation.removedCount()), now));
        return new Result(request.target(), roleId, mutation.version(), Long.toString(version), request.permissionCodes(), mutation.addedCount(), mutation.removedCount());
    }

    private long role(String roleId) {
        if (roleId == null || !roleId.matches("[1-9][0-9]{0,18}")) throw new IllegalArgumentException("invalid roleId");
        return Long.parseLong(roleId);
    }
}
