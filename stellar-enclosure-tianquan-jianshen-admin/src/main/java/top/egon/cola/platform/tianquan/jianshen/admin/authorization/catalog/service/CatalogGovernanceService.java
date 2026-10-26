package top.egon.cola.platform.tianquan.jianshen.admin.authorization.catalog.service;

import top.egon.cola.platform.tianquan.jianshen.contract.permission.annotation.PermissionResource;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.annotation.PermissionGroup;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.annotation.FieldPermissions;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.ResourceType;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.PermissionManifest;

import top.egon.cola.platform.tianquan.jianshen.admin.authorization.catalog.domain.vo.CatalogScopePageVO;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.catalog.domain.vo.CatalogDefinitionDetailVO;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.catalog.domain.vo.CatalogDefinitionPageVO;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.catalog.domain.vo.CatalogDefinitionVO;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import top.egon.cola.platform.tianquan.jianshen.admin.audit.domain.dto.AuditCommandDTO;
import top.egon.cola.platform.tianquan.jianshen.admin.audit.service.AuditQueryService;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.catalog.domain.dto.CatalogGovernanceCommandDTO;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.catalog.repository.CatalogGovernanceRepository;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.runtime.domain.vo.AuthorizationEventVO;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.runtime.repository.AuthorizationEventPublisher;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.runtime.state.repository.TenantAuthorizationStateRepository;
import top.egon.cola.platform.tianquan.jianshen.admin.registration.catalog.repository.CatalogAdministrationGuard;
import top.egon.cola.platform.tianquan.jianshen.admin.registration.catalog.service.PermissionCatalogActivationService;
import top.egon.cola.platform.tianquan.jianshen.admin.shared.domain.DatabaseClock;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.CatalogScope;
import top.egon.cola.platform.tianquan.jianshen.starter.security.Rbac3UserDetails;

import java.util.Map;

@Service
public class CatalogGovernanceService {
    public record Result(@PermissionResource(key = "tianquan-jianshen.field.authorization.catalog.service.CatalogGovernanceService.Result.target", type = ResourceType.FIELD,
                labelPage = "tianquan-jianshen.permissions", labelKey = "field.target")
        @FieldPermissions(valueType = PermissionManifest.JsonFieldType.OBJECT,
                plainRead = @PermissionGroup(codes = {"system:permission-catalog:manage"}))
        CatalogScope target, @PermissionResource(key = "tianquan-jianshen.field.authorization.catalog.service.CatalogGovernanceService.Result.kind", type = ResourceType.FIELD,
                labelPage = "tianquan-jianshen.permissions", labelKey = "field.kind")
        @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
                plainRead = @PermissionGroup(codes = {"system:permission-catalog:manage"}))
        CatalogGovernanceCommandDTO.Kind kind, @PermissionResource(key = "tianquan-jianshen.field.authorization.catalog.service.CatalogGovernanceService.Result.identity", type = ResourceType.FIELD,
                labelPage = "tianquan-jianshen.permissions", labelKey = "field.identity")
        @FieldPermissions(valueType = PermissionManifest.JsonFieldType.OBJECT,
                plainRead = @PermissionGroup(codes = {"system:permission-catalog:manage"}))
        CatalogDefinitionVO identity, @PermissionResource(key = "tianquan-jianshen.field.authorization.catalog.service.CatalogGovernanceService.Result.policyVersion", type = ResourceType.FIELD,
                labelPage = "tianquan-jianshen.permissions", labelKey = "field.policyVersion")
        @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
                plainRead = @PermissionGroup(codes = {"system:permission-catalog:manage"}))
        String policyVersion) { }
    private final CatalogAdministrationGuard guard;
    private final CatalogGovernanceRepository governance;
    private final TenantAuthorizationStateRepository policy;
    private final AuthorizationEventPublisher events;
    private final AuditQueryService audit;
    private final DatabaseClock clock;

    public CatalogGovernanceService(CatalogAdministrationGuard guard, CatalogGovernanceRepository governance,
            TenantAuthorizationStateRepository policy, AuthorizationEventPublisher events, AuditQueryService audit, DatabaseClock clock) {
        this.guard = guard;
        this.governance = governance;
        this.policy = policy;
        this.events = events;
        this.audit = audit;
        this.clock = clock;
    }

    @Transactional
    public CatalogScopePageVO scopes(long afterId, int limit, Rbac3UserDetails actor) {
        if (actor == null || actor.snapshot().permissionSnapshot() == null) {
            throw new top.egon.cola.platform.tianquan.jianshen.core.rule.Rbac3RuleViolation("AUTH_SNAPSHOT_NOT_READY");
        }
        guard.require(actor.snapshot().permissionSnapshot().catalogScope(), actor, PermissionCatalogActivationService.READ, clock.transactionNow());
        return governance.scopes(actor.tenantId(), afterId, limit);
    }

    @Transactional
    public CatalogDefinitionPageVO page(CatalogScope target, CatalogGovernanceCommandDTO.Kind kind, long afterId, int limit, Rbac3UserDetails actor) {
        guard.require(target, actor, PermissionCatalogActivationService.READ, clock.transactionNow());
        return governance.page(target, kind, afterId, limit);
    }

    @Transactional
    public CatalogDefinitionDetailVO detail(CatalogScope target, CatalogGovernanceCommandDTO.Kind kind, long id, Rbac3UserDetails actor) {
        guard.require(target, actor, PermissionCatalogActivationService.READ, clock.transactionNow());
        return governance.detail(target, kind, id);
    }

    @Transactional
    public Result mutate(CatalogGovernanceCommandDTO command, Rbac3UserDetails actor) {
        var now = clock.transactionNow();
        var scope = guard.require(command.target(), actor, PermissionCatalogActivationService.MANAGE, now);
        var mutation = governance.mutate(command, actor.rbac3UserId(), now);
        long version = policy.increment(Long.parseLong(command.target().tenantId()), actor.rbac3UserId());
        String trace = command.target().catalogScopeId() + ':' + command.identityId() + ':' + mutation.after().version();
        events.enqueue(new AuthorizationEventVO(command.target().tenantId(), "CATALOG_SCOPE", command.target().catalogScopeId(), "CATALOG_GOVERNANCE_CHANGED",
                Map.of("catalogScopeId", command.target().catalogScopeId(), "catalogVersion", Long.toString(scope.activeRevision()),
                        "policyVersion", Long.toString(version), "aggregateVersion", Long.toString(version)), trace));
        audit.record(new AuditCommandDTO(command.target().tenantId(), "CATALOG_" + command.kind() + '_' + command.action(), "SUCCESS", "INFO", "USER",
                actor.rbac3UserId(), command.kind().name(), command.identityId(), null, "ALLOW", trace, trace,
                Map.of("state", mutation.before().state(), "owner", mutation.before().producerId(), "version", mutation.before().version()),
                Map.of("catalogScopeId", command.target().catalogScopeId(), "key", mutation.after().key(), "state", mutation.after().state(),
                        "owner", mutation.after().producerId(), "version", mutation.after().version(), "policyVersion", Long.toString(version)), now));
        return new Result(command.target(), command.kind(), mutation.after(), Long.toString(version));
    }
}
