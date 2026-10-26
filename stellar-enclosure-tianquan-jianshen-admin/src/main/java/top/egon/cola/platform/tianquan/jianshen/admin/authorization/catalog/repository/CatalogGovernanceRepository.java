package top.egon.cola.platform.tianquan.jianshen.admin.authorization.catalog.repository;

import top.egon.cola.platform.tianquan.jianshen.admin.authorization.catalog.domain.vo.CatalogScopePageVO;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.catalog.domain.vo.CatalogDefinitionDetailVO;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.catalog.domain.vo.CatalogDefinitionPageVO;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.catalog.domain.vo.CatalogDefinitionVO;
import jakarta.persistence.EntityManager;
import jakarta.persistence.Query;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.catalog.domain.dto.CatalogGovernanceCommandDTO;
import top.egon.cola.platform.tianquan.jianshen.admin.registration.catalog.repository.PermissionCatalogScopeRepository;
import top.egon.cola.platform.tianquan.jianshen.admin.registration.catalog.domain.convertor.PermissionCatalogJson;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.CatalogScope;
import top.egon.cola.platform.tianquan.jianshen.core.rule.Rbac3RuleViolation;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** Governance changes stable identity state/owner only; immutable version definitions and role grants are preserved. */
@Repository
@Transactional(propagation = Propagation.MANDATORY)
public class CatalogGovernanceRepository {
    public record Mutation(CatalogDefinitionVO before, CatalogDefinitionVO after) { }

    private final EntityManager entityManager;
    private final PermissionCatalogScopeRepository scopes;
    private final PermissionCatalogJson json;

    public CatalogGovernanceRepository(EntityManager entityManager, PermissionCatalogScopeRepository scopes, PermissionCatalogJson json) {
        this.entityManager = entityManager;
        this.scopes = scopes;
        this.json = json;
    }

    public CatalogScopePageVO scopes(String tenant, long afterId, int limit) {
        if (afterId < 0 || limit < 1 || limit > 100) throw new IllegalArgumentException("invalid catalog pagination");
        List<?> rows = query("""
                select s.id,s.tenant_id,s.business_code,s.application_code,s.namespace_code,s.environment,s.application_id,
                       (select count(*) from rbac3_catalog_producer p where p.catalog_scope_id=s.id and p.enabled)
                  from rbac3_catalog_scope s join rbac3_application a on a.id=s.application_id
                 where s.tenant_id=:tenant and s.id>:after and s.status='ACTIVE' and a.status='ACTIVE'
                   and a.application_code=s.application_code and a.ddc_business_id=s.ddc_business_id and a.ddc_application_id=s.ddc_application_id
                 order by s.id
                """, Map.of("tenant", Long.parseLong(tenant), "after", afterId)).setMaxResults(limit + 1).getResultList();
        List<CatalogScopePageVO.Entry> entries = rows.stream().limit(limit).map(value -> {
            Object[] row = (Object[]) value;
            return new CatalogScopePageVO.Entry(new CatalogScope(row[0].toString(), row[1].toString(), row[2].toString(), row[3].toString(), row[4].toString(), row[5].toString()),
                    row[6].toString(), ((Number) row[7]).longValue());
        }).toList();
        return new CatalogScopePageVO(entries, rows.size() > limit ? entries.getLast().scope().catalogScopeId() : null);
    }

    public CatalogDefinitionPageVO page(CatalogScope target, CatalogGovernanceCommandDTO.Kind kind, long afterId, int limit) {
        if (afterId < 0 || limit < 1 || limit > 100) throw new IllegalArgumentException("invalid definition pagination");
        List<?> rows = query(select(kind) + " where catalog_scope_id=:scope and id>:after order by id",
                Map.of("scope", Long.parseLong(target.catalogScopeId()), "after", afterId)).setMaxResults(limit + 1).getResultList();
        boolean more = rows.size() > limit;
        List<CatalogDefinitionVO> values = rows.stream().limit(limit).map(this::definition).toList();
        return new CatalogDefinitionPageVO(target, kind, values, more ? values.getLast().id() : null);
    }

    public CatalogDefinitionDetailVO detail(CatalogScope target, CatalogGovernanceCommandDTO.Kind kind, long id) {
        CatalogDefinitionVO identity = require(target, kind, id);
        String table = kind == CatalogGovernanceCommandDTO.Kind.RESOURCE ? "rbac3_catalog_resource_version" : "rbac3_catalog_permission_version";
        String identityColumn = kind == CatalogGovernanceCommandDTO.Kind.RESOURCE ? "resource_id" : "permission_id";
        List<?> rows = query("select v.producer_version,v.definition_json::text from " + table + " v "
                + "join rbac3_catalog_activation_producer a on a.catalog_scope_id=v.catalog_scope_id and a.producer_id=v.producer_id and a.producer_version=v.producer_version "
                + "join rbac3_catalog_active_pointer h on h.catalog_scope_id=a.catalog_scope_id and h.activation_version=a.activation_version "
                + "where v.catalog_scope_id=:scope and v." + identityColumn + "=:id",
                Map.of("scope", Long.parseLong(target.catalogScopeId()), "id", id)).getResultList();
        if (rows.isEmpty()) return new CatalogDefinitionDetailVO(identity, null, null);
        if (rows.size() != 1) throw new Rbac3RuleViolation("AUTH_RUNTIME_UNAVAILABLE");
        Object[] row = (Object[]) rows.getFirst();
        return new CatalogDefinitionDetailVO(identity, row[0].toString(), json.readObject(row[1].toString()));
    }

    public Mutation mutate(CatalogGovernanceCommandDTO command, String actor, Instant now) {
        CatalogDefinitionVO previous = require(command.target(), command.kind(), Long.parseLong(command.identityId()));
        if (!previous.version().equals(command.expectedVersion())) throw new Rbac3RuleViolation("RESOURCE_VERSION_CONFLICT");
        if (previous.state().equals("RETIRED")) throw new Rbac3RuleViolation("RESOURCE_MANIFEST_CONFLICT");
        String owner = previous.producerId();
        String state = previous.state();
        var source = scopes.lockExistingOwner(command.target(), owner);
        switch (command.action()) {
            case DISABLE -> state = "DISABLED";
            case RETIRE -> {
                requireUnreferenced(command.target(), command.kind(), previous);
                state = "RETIRED";
            }
            case TRANSFER -> {
                if (owner.equals(command.targetProducerId())) throw new Rbac3RuleViolation("RESOURCE_MANIFEST_CONFLICT");
                var destination = scopes.lockOwner(command.target(), command.targetProducerId());
                var prefixes = command.kind() == CatalogGovernanceCommandDTO.Kind.RESOURCE ? destination.resourcePrefixes() : destination.permissionPrefixes();
                if (source.kind() != destination.kind() || prefixes.stream().noneMatch(previous.key()::startsWith)) {
                    throw new Rbac3RuleViolation("RESOURCE_MANIFEST_CONFLICT");
                }
                owner = destination.producerId();
                invalidateOwner(destination, actor, now);
            }
        }
        Map<String, Object> values = new LinkedHashMap<>();
        values.put("scope", Long.parseLong(command.target().catalogScopeId()));
        values.put("id", Long.parseLong(previous.id()));
        values.put("expected", Long.parseLong(command.expectedVersion()));
        values.put("owner", owner);
        values.put("state", state);
        values.put("actor", actor);
        values.put("now", now);
        String table = command.kind() == CatalogGovernanceCommandDTO.Kind.RESOURCE ? "rbac3_catalog_resource" : "rbac3_catalog_permission";
        int changed = query("update " + table + " set governance_state=:state,owner_producer_id=:owner,version=version+1,updated_at=:now,updated_by=:actor "
                + "where catalog_scope_id=:scope and id=:id and version=:expected", values).executeUpdate();
        if (changed != 1) throw new Rbac3RuleViolation("RESOURCE_VERSION_CONFLICT");
        invalidateOwner(source, actor, now);
        var next = new CatalogDefinitionVO(previous.id(), previous.key(), owner, state, Long.toString(Math.addExact(Long.parseLong(previous.version()), 1)), previous.type(), previous.meaning(), previous.activeProducerVersion());
        return new Mutation(previous, next);
    }

    private void requireUnreferenced(CatalogScope target, CatalogGovernanceCommandDTO.Kind kind, CatalogDefinitionVO identity) {
        Map<String, Object> values = Map.of("scope", Long.parseLong(target.catalogScopeId()), "id", Long.parseLong(identity.id()), "key", identity.key());
        String sql = kind == CatalogGovernanceCommandDTO.Kind.PERMISSION ? """
                select exists (
                    select 1 from rbac3_catalog_role_permission where catalog_scope_id=:scope and permission_id=:id and status='ACTIVE'
                    union all
                    select 1 from rbac3_catalog_resource_requirement r join rbac3_catalog_activation_producer a
                      on a.catalog_scope_id=r.catalog_scope_id and a.producer_id=r.producer_id and a.producer_version=r.producer_version
                      join rbac3_catalog_active_pointer h on h.catalog_scope_id=a.catalog_scope_id and h.activation_version=a.activation_version
                     where r.catalog_scope_id=:scope and r.permission_id=:id
                    union all
                    select 1 from rbac3_catalog_manifest m join rbac3_catalog_activation_producer a
                      on a.catalog_scope_id=m.catalog_scope_id and a.producer_id=m.producer_id and a.producer_version=m.producer_version
                      join rbac3_catalog_active_pointer h on h.catalog_scope_id=a.catalog_scope_id and h.activation_version=a.activation_version
                     where m.catalog_scope_id=:scope and m.canonical_manifest->'permissionReferences' @> jsonb_build_array(cast(:key as text))
                )
                """ : """
                select exists (
                    select 1 from rbac3_catalog_manifest m join rbac3_catalog_activation_producer a
                      on a.catalog_scope_id=m.catalog_scope_id and a.producer_id=m.producer_id and a.producer_version=m.producer_version
                      join rbac3_catalog_active_pointer h on h.catalog_scope_id=a.catalog_scope_id and h.activation_version=a.activation_version
                      cross join lateral jsonb_array_elements(m.canonical_manifest->'resourceReferences') ref
                     where m.catalog_scope_id=:scope and ref->>'key'=:key
                )
                """;
        if (kind == CatalogGovernanceCommandDTO.Kind.RESOURCE) values = Map.of("scope", values.get("scope"), "key", identity.key());
        if (!Boolean.FALSE.equals(query(sql, values).getSingleResult())) throw new Rbac3RuleViolation("RESOURCE_MANIFEST_CONFLICT");
    }

    private void invalidateOwner(PermissionCatalogScopeRepository.Owner owner, String actor, Instant now) {
        int changed = query("""
                update rbac3_catalog_producer set version=version+1,updated_at=:now,updated_by=:actor
                 where catalog_scope_id=:scope and producer_id=:producer and version=:expected
                """, Map.of("scope", Long.parseLong(owner.scope().catalogScopeId()), "producer", owner.producerId(),
                "expected", owner.ownerVersion(), "now", now, "actor", actor)).executeUpdate();
        if (changed != 1) throw new Rbac3RuleViolation("RESOURCE_VERSION_CONFLICT");
    }

    private CatalogDefinitionVO require(CatalogScope target, CatalogGovernanceCommandDTO.Kind kind, long id) {
        var rows = query(select(kind) + " where catalog_scope_id=:scope and id=:id for update",
                Map.of("scope", Long.parseLong(target.catalogScopeId()), "id", id)).getResultList();
        if (rows.size() != 1) throw new Rbac3RuleViolation("RESOURCE_NOT_FOUND");
        return definition(rows.getFirst());
    }

    private String select(CatalogGovernanceCommandDTO.Kind kind) {
        String table = kind == CatalogGovernanceCommandDTO.Kind.RESOURCE ? "rbac3_catalog_resource" : "rbac3_catalog_permission";
        String identity = kind == CatalogGovernanceCommandDTO.Kind.RESOURCE ? "resource_id" : "permission_id";
        String columns = kind == CatalogGovernanceCommandDTO.Kind.RESOURCE
                ? "id,registration_key,owner_producer_id,governance_state,version,resource_type,''"
                : "id,permission_code,owner_producer_id,governance_state,version,'PERMISSION',meaning";
        String active = "(select v.producer_version from " + table + "_version v join rbac3_catalog_activation_producer a "
                + "on a.catalog_scope_id=v.catalog_scope_id and a.producer_id=v.producer_id and a.producer_version=v.producer_version "
                + "join rbac3_catalog_active_pointer h on h.catalog_scope_id=a.catalog_scope_id and h.activation_version=a.activation_version "
                + "where v.catalog_scope_id=" + table + ".catalog_scope_id and v." + identity + "=" + table + ".id)";
        return "select " + columns + ',' + active + " from " + table;
    }

    private CatalogDefinitionVO definition(Object value) {
        Object[] row = (Object[]) value;
        return new CatalogDefinitionVO(row[0].toString(), row[1].toString(), row[2].toString(), row[3].toString(), row[4].toString(), row[5].toString(), row[6].toString(), row[7] == null ? null : row[7].toString());
    }

    private Query query(String sql, Map<String, Object> values) {
        Query query = entityManager.createNativeQuery(sql);
        values.forEach(query::setParameter);
        return query;
    }
}
