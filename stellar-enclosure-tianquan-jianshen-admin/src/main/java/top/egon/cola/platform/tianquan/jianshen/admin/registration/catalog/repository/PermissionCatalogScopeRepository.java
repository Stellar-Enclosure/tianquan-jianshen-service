package top.egon.cola.platform.tianquan.jianshen.admin.registration.catalog.repository;

import jakarta.persistence.EntityManager;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import top.egon.cola.platform.tianquan.jianshen.admin.registration.catalog.domain.PermissionCatalogCaller;
import top.egon.cola.platform.tianquan.jianshen.admin.registration.catalog.domain.convertor.PermissionCatalogJson;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.CatalogScope;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.PermissionManifest;
import top.egon.cola.platform.tianquan.jianshen.core.rule.Rbac3RuleViolation;

import java.time.Instant;
import java.util.List;
import java.util.Set;

/** Locks scope, producer and exact machine grant inside the owning command transaction. */
@Repository
public class PermissionCatalogScopeRepository {

    public record Owner(CatalogScope scope, long applicationId, String producerId, PermissionManifest.ProducerKind kind,
                        List<String> resourcePrefixes, List<String> permissionPrefixes, List<String> messagePrefixes,
                        List<String> expectedModules, long producerRevision, long ownerVersion,
                        long activeRevision, long policyVersion) {
        public Owner {
            resourcePrefixes = List.copyOf(resourcePrefixes);
            permissionPrefixes = List.copyOf(permissionPrefixes);
            messagePrefixes = List.copyOf(messagePrefixes);
            expectedModules = List.copyOf(expectedModules);
        }
    }

    public record Grant(long id, long version, Set<String> capabilities, Set<String> allowedSourceRefs,
                        boolean allowPermissionExpansion) {
        public Grant {
            capabilities = Set.copyOf(capabilities);
            allowedSourceRefs = Set.copyOf(allowedSourceRefs);
        }

        public void require(PermissionCatalogCaller.Capability capability) {
            if (!capabilities.contains(capability.name())) throw new Rbac3RuleViolation("SERVICE_IDENTITY_DENIED");
        }
    }

    public record AuthorizedOwner(Owner owner, Grant grant) { }

    public record ScopeState(CatalogScope scope, long applicationId, long activeRevision, long policyVersion) { }

    private final EntityManager entityManager;
    private final PermissionCatalogJson json;

    public PermissionCatalogScopeRepository(EntityManager entityManager, PermissionCatalogJson json) {
        this.entityManager = entityManager;
        this.json = json;
    }

    @Transactional(propagation = Propagation.MANDATORY)
    public AuthorizedOwner authorize(CatalogScope target, String producerId, PermissionCatalogCaller caller,
                                     PermissionCatalogCaller.Capability capability, Instant now) {
        caller.require(target, capability, now);
        Owner owner = lockOwner(target, producerId);
        List<?> rows = entityManager.createNativeQuery("""
                        select id, version, capabilities::text, allowed_source_refs::text, allow_permission_expansion
                          from rbac3_catalog_service_grant
                         where catalog_scope_id = :scope and producer_id = :producer
                           and principal_binding_digest = :binding and issuer = :issuer
                           and client_id = :client and resource_uri = :resource and enabled
                         for share
                        """)
                .setParameter("scope", Long.parseLong(target.catalogScopeId())).setParameter("producer", producerId)
                .setParameter("binding", caller.bindingDigest()).setParameter("issuer", caller.issuer().toString())
                .setParameter("client", caller.principal().clientId()).setParameter("resource", caller.principal().resourceUri().toString())
                .getResultList();
        if (rows.size() != 1) throw new Rbac3RuleViolation("SERVICE_IDENTITY_DENIED");
        Object[] row = (Object[]) rows.getFirst();
        Grant grant = new Grant(number(row[0]), number(row[1]), Set.copyOf(json.strings(row[2].toString())),
                Set.copyOf(json.strings(row[3].toString())), (Boolean) row[4]);
        grant.require(capability);
        return new AuthorizedOwner(owner, grant);
    }

    @Transactional(propagation = Propagation.MANDATORY)
    public ScopeState lockScope(CatalogScope target) {
        return scope(target, true);
    }

    @Transactional(propagation = Propagation.MANDATORY, readOnly = true)
    public ScopeState readScope(CatalogScope target) {
        return scope(target, false);
    }

    private ScopeState scope(CatalogScope target, boolean lock) {
        long scopeId = Long.parseLong(target.catalogScopeId());
        List<?> scopes = entityManager.createNativeQuery("""
                        select s.id, s.tenant_id, s.business_code, s.application_code, s.namespace_code,
                               s.environment, s.application_id
                          from rbac3_catalog_scope s join rbac3_application a on a.id = s.application_id
                         where s.id = :scope and s.status = 'ACTIVE' and a.status = 'ACTIVE'
                           and a.application_code = s.application_code and a.ddc_business_id = s.ddc_business_id
                           and a.ddc_application_id = s.ddc_application_id
                        """ + (lock ? " for update of s" : "")).setParameter("scope", scopeId).getResultList();
        if (scopes.size() != 1) throw new Rbac3RuleViolation("APPLICATION_BINDING_DENIED");
        Object[] scope = (Object[]) scopes.getFirst();
        CatalogScope stored = new CatalogScope(scope[0].toString(), scope[1].toString(), scope[2].toString(),
                scope[3].toString(), scope[4].toString(), scope[5].toString());
        if (!target.equals(stored)) throw new Rbac3RuleViolation("APPLICATION_BINDING_DENIED");
        List<?> pointers = entityManager.createNativeQuery("""
                        select revision, policy_version from rbac3_catalog_active_pointer where catalog_scope_id = :scope
                        """ + (lock ? " for update" : "")).setParameter("scope", scopeId).getResultList();
        if (pointers.size() != 1) throw new Rbac3RuleViolation("AUTH_SNAPSHOT_NOT_READY");
        Object[] pointer = (Object[]) pointers.getFirst();
        return new ScopeState(target, number(scope[6]), number(pointer[0]), number(pointer[1]));
    }

    @Transactional(propagation = Propagation.MANDATORY)
    public Owner lockOwner(CatalogScope target, String producerId) {
        return owner(target, producerId, true, true);
    }

    @Transactional(propagation = Propagation.MANDATORY)
    public Owner lockExistingOwner(CatalogScope target, String producerId) {
        return owner(target, producerId, false, true);
    }

    @Transactional(propagation = Propagation.MANDATORY, readOnly = true)
    public Owner readExistingOwner(CatalogScope target, String producerId) {
        return owner(target, producerId, false, false);
    }

    private Owner owner(CatalogScope target, String producerId, boolean enabledOnly, boolean lock) {
        ScopeState scope = scope(target, lock);
        List<?> owners = entityManager.createNativeQuery("""
                        select kind, owned_key_prefixes::text, owned_permission_prefixes::text,
                               owned_message_prefixes::text, expected_modules::text, current_revision, version
                          from rbac3_catalog_producer where catalog_scope_id = :scope and producer_id = :producer and (not :enabledOnly or enabled)
                        """ + (lock ? " for update" : "")).setParameter("scope", Long.parseLong(target.catalogScopeId())).setParameter("producer", producerId)
                .setParameter("enabledOnly", enabledOnly).getResultList();
        if (owners.size() != 1) throw new Rbac3RuleViolation("SERVICE_IDENTITY_DENIED");
        Object[] owner = (Object[]) owners.getFirst();
        return new Owner(target, scope.applicationId(), producerId, PermissionManifest.ProducerKind.valueOf(owner[0].toString()),
                json.strings(owner[1].toString()), json.strings(owner[2].toString()), json.strings(owner[3].toString()),
                json.strings(owner[4].toString()), number(owner[5]), number(owner[6]), scope.activeRevision(), scope.policyVersion());
    }

    @Transactional(propagation = Propagation.MANDATORY)
    public long advanceProducer(Owner owner, String actor, Instant now) {
        long next = Math.addExact(owner.producerRevision(), 1);
        int updated = entityManager.createNativeQuery("""
                        update rbac3_catalog_producer set current_revision = :next, version = version + 1,
                               updated_at = :now, updated_by = :actor
                         where catalog_scope_id = :scope and producer_id = :producer
                           and current_revision = :expected and version = :version and enabled
                        """).setParameter("next", next).setParameter("now", now).setParameter("actor", actor)
                .setParameter("scope", Long.parseLong(owner.scope().catalogScopeId())).setParameter("producer", owner.producerId())
                .setParameter("expected", owner.producerRevision()).setParameter("version", owner.ownerVersion()).executeUpdate();
        if (updated != 1) throw new Rbac3RuleViolation("RESOURCE_VERSION_CONFLICT");
        return next;
    }

    private static long number(Object value) {
        return ((Number) value).longValue();
    }
}
