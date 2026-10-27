package top.egon.cola.platform.tianquan.jianshen.admin.audit.repository;

import jakarta.persistence.EntityManager;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import top.egon.cola.platform.tianquan.jianshen.starter.permission.PermissionDenialDiagnostic;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** Resolves direct role grants only while the original authority versions are still locked and current. */
@Repository
public class DecisionPermissionSourceRepository {
    private final EntityManager entityManager;

    public DecisionPermissionSourceRepository(EntityManager entityManager) { this.entityManager = entityManager; }

    public record Sources(String status, Map<String, List<String>> rolesByPermission, List<Map<String, Object>> dataScopeRules) {
        public Sources(String status, Map<String, List<String>> rolesByPermission) { this(status, rolesByPermission, List.of()); }
        public Sources {
            rolesByPermission = Map.copyOf(rolesByPermission);
            dataScopeRules = dataScopeRules.stream().map(Map::copyOf).toList();
        }
    }

    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public Sources resolve(PermissionDenialDiagnostic event) {
        var scope = event.scope();
        long scopeId = Long.parseLong(scope.catalogScopeId());
        long tenant = Long.parseLong(scope.tenantId());
        var scopeRows = entityManager.createNativeQuery("""
                select id from rbac3_catalog_scope
                 where id=:scope and tenant_id=:tenant and business_code=:business and application_code=:application
                   and namespace_code=:namespace and environment=:environment and status='ACTIVE' for share nowait
                """).setParameter("scope", scopeId).setParameter("tenant", tenant)
                .setParameter("business", scope.businessCode()).setParameter("application", scope.applicationCode())
                .setParameter("namespace", scope.namespaceCode()).setParameter("environment", scope.environment()).getResultList();
        if (scopeRows.size() != 1) return new Sources("SCOPE_CHANGED", Map.of());
        var policies = entityManager.createNativeQuery("""
                select policy_version from rbac3_tenant_authorization_state where tenant_id=:tenant for share nowait
                """).setParameter("tenant", tenant).getResultList();
        if (policies.size() != 1 || ((Number) policies.getFirst()).longValue() != Long.parseLong(event.policyVersion())) {
            return new Sources("POLICY_VERSION_CHANGED", Map.of());
        }
        var users = entityManager.createNativeQuery("""
                select auth_version from rbac3_user where tenant_id=:tenant and id=:user and status='ACTIVE' for share nowait
                """).setParameter("tenant", tenant).setParameter("user", Long.parseLong(event.userId())).getResultList();
        if (users.size() != 1 || ((Number) users.getFirst()).longValue() != Long.parseLong(event.authVersion())) {
            return new Sources("AUTH_VERSION_CHANGED", Map.of());
        }
        var activations = entityManager.createNativeQuery("""
                select activation_version from rbac3_catalog_active_pointer where catalog_scope_id=:scope
                """).setParameter("scope", scopeId).getResultList();
        if (activations.size() != 1 || ((Number) activations.getFirst()).longValue() != Long.parseLong(event.catalogVersion())) {
            return new Sources("CATALOG_VERSION_CHANGED", Map.of());
        }
        Set<String> granted = event.permissionFacts().stream().filter(PermissionDenialDiagnostic.PermissionFact::granted)
                .map(PermissionDenialDiagnostic.PermissionFact::code).collect(java.util.stream.Collectors.toUnmodifiableSet());
        if (granted.isEmpty()) return new Sources("VERIFIED", Map.of());
        if (event.effectiveRoleIds().isEmpty()) return new Sources("INCOMPLETE", Map.of());
        var rows = entityManager.createNativeQuery("""
                select distinct g.role_id,p.permission_code from rbac3_catalog_role_permission g
                  join rbac3_catalog_role_binding b on b.catalog_scope_id=g.catalog_scope_id and b.role_id=g.role_id and b.enabled
                  join rbac3_catalog_permission p on p.catalog_scope_id=g.catalog_scope_id and p.id=g.permission_id and p.governance_state='ACTIVE'
                  join rbac3_catalog_activation_producer ap on ap.catalog_scope_id=p.catalog_scope_id and ap.producer_id=p.owner_producer_id
                  join rbac3_catalog_producer producer on producer.catalog_scope_id=ap.catalog_scope_id and producer.producer_id=ap.producer_id and producer.enabled
                  join rbac3_catalog_permission_version pv on pv.catalog_scope_id=ap.catalog_scope_id and pv.producer_id=ap.producer_id
                       and pv.producer_version=ap.producer_version and pv.permission_id=p.id
                 where g.catalog_scope_id=:scope and ap.activation_version=:catalog and g.role_id in (:roles)
                   and p.permission_code in (:codes) and g.status='ACTIVE'
                   and g.valid_from<=:at and (g.valid_to is null or g.valid_to>:at)
                """).setParameter("scope", scopeId).setParameter("catalog", Long.parseLong(event.catalogVersion()))
                .setParameter("roles", event.effectiveRoleIds().stream().map(Long::valueOf).toList())
                .setParameter("codes", granted).setParameter("at", event.snapshotAt()).getResultList();
        var sources = new java.util.TreeMap<String, java.util.TreeSet<String>>();
        for (Object value : rows) {
            Object[] row = (Object[]) value;
            String code = row[1].toString();
            if (!granted.contains(code)) return new Sources("INCOMPLETE", Map.of());
            sources.computeIfAbsent(code, ignored -> new java.util.TreeSet<>()).add(row[0].toString());
        }
        if (!sources.keySet().equals(granted)) return new Sources("INCOMPLETE", Map.of());
        var result = new java.util.TreeMap<String, List<String>>();
        sources.forEach((code, roles) -> result.put(code, List.copyOf(roles)));
        List<Map<String, Object>> dataRules = List.of();
        if ("DATA_SCOPE_POLICY".equals(event.decisionKind())) {
            var ruleRows = entityManager.createNativeQuery("""
                    select d.id,d.role_id,d.scope_type,count(r.ref_id),coalesce(d.directory_snapshot_version,0)
                      from rbac3_data_rule d
                      join rbac3_catalog_permission p on p.catalog_scope_id=d.catalog_scope_id and p.id=d.permission_id
                      left join rbac3_data_rule_ref r on r.tenant_id=d.tenant_id and r.data_rule_id=d.id
                     where d.catalog_scope_id=:scope and d.role_id in (:roles) and p.permission_code in (:codes)
                       and d.status='ACTIVE' and d.valid_from<=:at and (d.valid_to is null or d.valid_to>:at)
                     group by d.id,d.role_id,d.scope_type,d.directory_snapshot_version order by d.id
                    """).setParameter("scope", scopeId)
                    .setParameter("roles", event.effectiveRoleIds().stream().map(Long::valueOf).toList())
                    .setParameter("codes", granted).setParameter("at", event.snapshotAt()).getResultList();
            var matched = new java.util.ArrayList<Map<String, Object>>();
            for (Object value : ruleRows) {
                Object[] row = (Object[]) value;
                matched.add(Map.of("ruleId", row[0].toString(), "roleId", row[1].toString(), "scopeType", row[2].toString(),
                        "referenceCount", ((Number) row[3]).longValue(), "directoryVersion", row[4].toString()));
            }
            dataRules = List.copyOf(matched);
        }
        return new Sources("VERIFIED", result, dataRules);
    }
}
