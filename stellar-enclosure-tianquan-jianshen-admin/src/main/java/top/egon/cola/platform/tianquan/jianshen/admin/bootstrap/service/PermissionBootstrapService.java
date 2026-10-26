package top.egon.cola.platform.tianquan.jianshen.admin.bootstrap.service;

import org.springframework.transaction.annotation.Transactional;
import top.egon.cola.platform.tianquan.jianshen.admin.audit.domain.dto.AuditCommandDTO;
import top.egon.cola.platform.tianquan.jianshen.admin.audit.service.AuditQueryService;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.grant.rolepermission.domain.dto.ReplaceRolePermissionsRequestDTO;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.grant.rolepermission.repository.RolePermissionGrantRepository;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.runtime.domain.vo.AuthorizationEventVO;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.runtime.repository.AuthorizationEventPublisher;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.runtime.state.repository.TenantAuthorizationStateRepository;
import top.egon.cola.platform.tianquan.jianshen.admin.bootstrap.domain.dto.PermissionAdministratorBootstrapCommandDTO;
import top.egon.cola.platform.tianquan.jianshen.admin.bootstrap.domain.dto.PermissionCatalogBootstrapCommandDTO;
import top.egon.cola.platform.tianquan.jianshen.admin.bootstrap.domain.vo.PermissionBootstrapReceiptVO;
import top.egon.cola.platform.tianquan.jianshen.admin.bootstrap.repository.PermissionBootstrapRepository;
import top.egon.cola.platform.tianquan.jianshen.admin.registration.catalog.domain.convertor.PermissionCatalogJson;
import top.egon.cola.platform.tianquan.jianshen.admin.registration.catalog.repository.PermissionCatalogScopeRepository;
import top.egon.cola.platform.tianquan.jianshen.admin.shared.domain.DatabaseClock;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.CanonicalJson;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;

/** Invoked only by the explicit operator command configuration, never by startup or ordinary registration. */
public class PermissionBootstrapService {
    private static final String ACTOR = PermissionBootstrapRepository.ACTOR;
    private final PermissionBootstrapRepository bootstrap;
    private final PermissionCatalogScopeRepository scopes;
    private final RolePermissionGrantRepository grants;
    private final TenantAuthorizationStateRepository policy;
    private final AuthorizationEventPublisher events;
    private final AuditQueryService audit;
    private final DatabaseClock clock;
    private final PermissionCatalogJson json;
    private final String databaseBindingDigest;

    public PermissionBootstrapService(PermissionBootstrapRepository bootstrap, PermissionCatalogScopeRepository scopes,
            RolePermissionGrantRepository grants, TenantAuthorizationStateRepository policy, AuthorizationEventPublisher events,
            AuditQueryService audit, DatabaseClock clock, PermissionCatalogJson json, String databaseBindingDigest) {
        this.bootstrap = bootstrap; this.scopes = scopes; this.grants = grants; this.policy = policy;
        this.events = events; this.audit = audit; this.clock = clock; this.json = json;
        if (databaseBindingDigest == null || !databaseBindingDigest.matches("[0-9a-f]{64}")) throw new IllegalArgumentException("database binding digest required");
        this.databaseBindingDigest = databaseBindingDigest;
    }

    @Transactional
    public PermissionBootstrapReceiptVO catalog(PermissionCatalogBootstrapCommandDTO command, boolean existingReceipt) {
        String digest = digest(command);
        bootstrap.lockTenant(command.target().tenantId());
        var previous = bootstrap.original(command.target().tenantId(), command.operationId(), digest);
        if (previous.isPresent()) return previous.get();
        if (existingReceipt) throw new IllegalStateException("BOOTSTRAP_COMMITTED_RECEIPT_MISSING");
        Instant now = clock.transactionNow();
        var facts = bootstrap.initializeCatalog(command, now);
        var receipt = new PermissionBootstrapReceiptVO(1, "B0", command.operationId(), digest, command.target(), command.applicationId(),
                command.ddcBusinessId(), command.ddcApplicationId(), command.producers().stream().map(PermissionCatalogBootstrapCommandDTO.Producer::producerId).toList(), facts, now);
        record(receipt, "PERMISSION_CATALOG_BOOTSTRAPPED");
        return receipt;
    }

    @Transactional
    public PermissionBootstrapReceiptVO administrator(PermissionAdministratorBootstrapCommandDTO command, boolean existingReceipt) {
        String digest = digest(command);
        bootstrap.lockTenant(command.target().tenantId());
        var previous = bootstrap.original(command.target().tenantId(), command.operationId(), digest);
        if (previous.isPresent()) return previous.get();
        if (existingReceipt) throw new IllegalStateException("BOOTSTRAP_COMMITTED_RECEIPT_MISSING");
        bootstrap.requireAdministratorNotInitialized(command.target());
        var scope = scopes.lockScope(command.target());
        if (scope.activeRevision() <= 0 || !command.expectedActiveRevision().equals(Long.toString(scope.activeRevision()))) {
            throw new IllegalStateException("BOOTSTRAP_ACTIVE_REVISION_CONFLICT");
        }
        bootstrap.requireQualifiedActiveCatalog(scope);
        policy.requireForUpdate(Long.parseLong(command.target().tenantId()));
        Instant now = clock.transactionNow();
        Instant from = command.validFrom() == null ? now : command.validFrom();
        if (command.validTo() != null && (!command.validTo().isAfter(from) || !command.validTo().isAfter(now))
                || command.activateRole() && from.isAfter(now)) throw new IllegalArgumentException("invalid active bootstrap interval");
        grants.requireActiveCodes(command.target(), command.permissionCodes());
        var actor = bootstrap.initializeAdministrator(scope, command, from, now);
        var mutation = grants.replace(scope, actor.roleId(), new ReplaceRolePermissionsRequestDTO(command.target(), command.permissionCodes(), "0", from, command.validTo()), ACTOR, now);
        long policyVersion = policy.increment(Long.parseLong(command.target().tenantId()), ACTOR);
        events.enqueue(new AuthorizationEventVO(command.target().tenantId(), "ROLE", Long.toString(actor.roleId()), "ROLE_PERMISSION_CHANGED",
                Map.of("catalogScopeId", command.target().catalogScopeId(), "roleId", Long.toString(actor.roleId()),
                        "permissionVersion", mutation.version(), "policyVersion", Long.toString(policyVersion)), command.operationId()));
        var application = bootstrap.application(command.target());
        Map<String, String> facts = new LinkedHashMap<>();
        facts.put("userId", Long.toString(actor.userId())); facts.put("roleId", Long.toString(actor.roleId()));
        facts.put("assignmentId", Long.toString(actor.assignmentId())); facts.put("authVersion", Long.toString(actor.authVersion()));
        facts.put("permissionVersion", mutation.version()); facts.put("policyVersion", Long.toString(policyVersion));
        facts.put("activeRevision", command.expectedActiveRevision()); facts.put("activeRole", Boolean.toString(command.activateRole()));
        facts.put("permissionCodesDigest", CanonicalJson.digest(command.permissionCodes()));
        var receipt = new PermissionBootstrapReceiptVO(1, "B1", command.operationId(), digest, command.target(), Long.toString(application.applicationId()),
                application.businessId(), application.applicationPublicId(), bootstrap.producerIds(command.target()), facts, now);
        record(receipt, "PERMISSION_ADMIN_BOOTSTRAPPED");
        return receipt;
    }

    public String digest(Object command) { return CanonicalJson.digest(Map.of("command", json.readObject(json.write(command)), "databaseBindingDigest", databaseBindingDigest)); }

    private void record(PermissionBootstrapReceiptVO receipt, String event) {
        audit.record(new AuditCommandDTO(receipt.target().tenantId(), event, "SUCCESS", "HIGH", "SYSTEM", ACTOR,
                "CATALOG_SCOPE", receipt.target().catalogScopeId(), null, "ALLOW", receipt.operationId(), receipt.operationId(), Map.of(),
                Map.of("commandDigest", receipt.commandDigest(), "receipt", json.readObject(json.write(receipt))), receipt.completedAt()));
    }
}
