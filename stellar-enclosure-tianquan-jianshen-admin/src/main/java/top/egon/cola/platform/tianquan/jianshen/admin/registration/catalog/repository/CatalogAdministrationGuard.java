package top.egon.cola.platform.tianquan.jianshen.admin.registration.catalog.repository;

import jakarta.persistence.EntityManager;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.runtime.state.repository.TenantAuthorizationStateRepository;
import top.egon.cola.platform.tianquan.jianshen.admin.registration.catalog.repository.PermissionCatalogScopeRepository;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.CatalogScope;
import top.egon.cola.platform.tianquan.jianshen.core.rule.Rbac3RuleViolation;
import top.egon.cola.platform.tianquan.jianshen.starter.security.Rbac3UserDetails;

import java.time.Instant;

/** Rechecks the already verified USER snapshot at the local mutation fence, in scope/tenant/user lock order. */
@Component
@Transactional(propagation = Propagation.MANDATORY)
public class CatalogAdministrationGuard {
    private final PermissionCatalogScopeRepository scopes;
    private final TenantAuthorizationStateRepository policy;
    private final EntityManager entityManager;

    public CatalogAdministrationGuard(PermissionCatalogScopeRepository scopes, TenantAuthorizationStateRepository policy, EntityManager entityManager) {
        this.scopes = scopes;
        this.policy = policy;
        this.entityManager = entityManager;
    }

    public PermissionCatalogScopeRepository.ScopeState require(CatalogScope target, Rbac3UserDetails actor, String permission, Instant now) {
        return require(target, actor, permission, now, true);
    }

    public PermissionCatalogScopeRepository.ScopeState requireRead(CatalogScope target, Rbac3UserDetails actor, String permission, Instant now) {
        return require(target, actor, permission, now, false);
    }

    private PermissionCatalogScopeRepository.ScopeState require(CatalogScope target, Rbac3UserDetails actor, String permission, Instant now, boolean lock) {
        if (actor == null || !target.tenantId().equals(actor.tenantId()) || !actor.hasPermission(permission)
                || !now.isBefore(actor.identity().expiresAt()) || !now.isBefore(actor.snapshot().expiresAt())) {
            throw new Rbac3RuleViolation("PERMISSION_DENIED");
        }
        var scope = lock ? scopes.lockScope(target) : scopes.readScope(target);
        var state = lock ? policy.requireForUpdate(Long.parseLong(target.tenantId())) : policy.require(Long.parseLong(target.tenantId()));
        if (state.getPolicyVersion() != actor.policyVersion()) {
            throw new Rbac3RuleViolation("AUTH_SNAPSHOT_NOT_READY");
        }
        var rows = entityManager.createNativeQuery("""
                select auth_version from rbac3_user where id=:user and tenant_id=:tenant and identity_sub=:subject and status='ACTIVE'
                """ + (lock ? " for update" : "")).setParameter("user", Long.parseLong(actor.rbac3UserId())).setParameter("tenant", Long.parseLong(target.tenantId()))
                .setParameter("subject", actor.identitySub()).getResultList();
        if (rows.size() != 1 || ((Number) rows.getFirst()).longValue() != actor.authVersion()) {
            throw new Rbac3RuleViolation("AUTH_SNAPSHOT_NOT_READY");
        }
        return scope;
    }
}
