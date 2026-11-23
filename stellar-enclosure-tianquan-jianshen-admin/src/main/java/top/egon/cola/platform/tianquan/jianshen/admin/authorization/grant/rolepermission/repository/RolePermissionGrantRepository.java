package top.egon.cola.platform.tianquan.jianshen.admin.authorization.grant.rolepermission.repository;

import top.egon.cola.platform.tianquan.jianshen.admin.authorization.grant.rolepermission.domain.vo.RolePermissionGrantViewVO;
import jakarta.persistence.EntityManager;
import jakarta.persistence.Query;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.grant.rolepermission.domain.dto.ReplaceRolePermissionsRequestDTO;
import top.egon.cola.platform.tianquan.jianshen.admin.registration.catalog.repository.PermissionCatalogScopeRepository;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.CatalogScope;
import top.egon.cola.platform.tianquan.jianshen.core.rule.Rbac3RuleViolation;

import java.time.Instant;
import java.time.OffsetDateTime;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

/** Direct permission grants are the only grant facts written here. Resource identities never become role grants. */
@Repository
@Transactional(propagation = Propagation.MANDATORY)
public class RolePermissionGrantRepository {
    public record Mutation(String version, long addedCount, long removedCount) { }

    private final EntityManager entityManager;

    public RolePermissionGrantRepository(EntityManager entityManager) { this.entityManager = entityManager; }

    public RolePermissionGrantViewVO read(PermissionCatalogScopeRepository.ScopeState scope, long role) {
        requireRole(scope, role, false);
        return readGrants(scope, role, false);
    }

    private RolePermissionGrantViewVO readGrants(PermissionCatalogScopeRepository.ScopeState scope, long role, boolean lockBinding) {
        Map<String, Object> values = base(scope.scope(), role);
        var binding = query("select permission_version,enabled from rbac3_catalog_role_binding where catalog_scope_id=:scope and role_id=:role"
                + (lockBinding ? " for update" : ""), values).getResultList();
        long version = binding.isEmpty() ? 0 : ((Number) ((Object[]) binding.getFirst())[0]).longValue();
        if (!binding.isEmpty() && !Boolean.TRUE.equals(((Object[]) binding.getFirst())[1])) throw new Rbac3RuleViolation("PERMISSION_DENIED");
        List<?> rows = query("""
                select p.permission_code,g.valid_from,g.valid_to from rbac3_catalog_role_permission g
                  join rbac3_catalog_permission p on p.catalog_scope_id=g.catalog_scope_id and p.id=g.permission_id
                 where g.catalog_scope_id=:scope and g.role_id=:role and g.status='ACTIVE' order by p.permission_code
                """, values).setMaxResults(10_001).getResultList();
        if (rows.size() > 10_000) throw new Rbac3RuleViolation("AUTH_RUNTIME_UNAVAILABLE");
        List<RolePermissionGrantViewVO.Grant> grants = rows.stream().map(value -> {
            Object[] row = (Object[]) value;
            return new RolePermissionGrantViewVO.Grant(row[0].toString(), instant(row[1]), row[2] == null ? null : instant(row[2]));
        }).toList();
        return new RolePermissionGrantViewVO(scope.scope(), Long.toString(role), Long.toString(version), Long.toString(scope.activeRevision()), grants);
    }

    public Mutation replace(PermissionCatalogScopeRepository.ScopeState scope, long role, ReplaceRolePermissionsRequestDTO request, String actor, Instant now) {
        requireRole(scope, role, true);
        Instant from = request.validFrom() == null ? now : request.validFrom();
        if (request.validTo() != null && !request.validTo().isAfter(from)) throw new IllegalArgumentException("invalid grant interval");
        Map<String, Object> values = base(scope.scope(), role);
        values.put("tenant", Long.parseLong(scope.scope().tenantId()));
        values.put("application", scope.applicationId());
        values.put("actor", actor);
        values.put("now", now);
        query("""
                insert into rbac3_catalog_role_binding(catalog_scope_id,role_id,tenant_id,application_id,created_at,created_by,updated_at,updated_by)
                values(:scope,:role,:tenant,:application,:now,:actor,:now,:actor) on conflict(catalog_scope_id,role_id) do nothing
                """, values).executeUpdate();
        RolePermissionGrantViewVO previous = readGrants(scope, role, true);
        if (!previous.version().equals(request.expectedVersion())) throw new Rbac3RuleViolation("RESOURCE_VERSION_CONFLICT");
        List<Long> permissionIds = activePermissionIds(scope.scope(), request.permissionCodes());
        values = base(scope.scope(), role);
        values.put("actor", actor);
        values.put("now", now);
        String retained = "";
        if (!permissionIds.isEmpty()) {
            values.put("ids", permissionIds);
            retained = " and permission_id not in (:ids)";
        }
        query("""
                update rbac3_catalog_role_permission set status='DISABLED',version=version+1,updated_at=:now,updated_by=:actor
                 where catalog_scope_id=:scope and role_id=:role and status='ACTIVE'
                """ + retained, values).executeUpdate();
        if (!permissionIds.isEmpty()) {
            values.put("from", from);
            values.put("until", request.validTo());
            query("""
                    insert into rbac3_catalog_role_permission(catalog_scope_id,role_id,permission_id,status,valid_from,valid_to,created_at,created_by,updated_at,updated_by)
                    select :scope,:role,p.id,'ACTIVE',:from,:until,:now,:actor,:now,:actor
                      from rbac3_catalog_permission p where p.catalog_scope_id=:scope and p.id in (:ids)
                    on conflict(catalog_scope_id,role_id,permission_id) do update set status='ACTIVE',valid_from=excluded.valid_from,
                        valid_to=excluded.valid_to,version=rbac3_catalog_role_permission.version+1,updated_at=excluded.updated_at,updated_by=excluded.updated_by
                    """, values).executeUpdate();
        }
        long expected = Long.parseLong(request.expectedVersion());
        int changed = query("""
                update rbac3_catalog_role_binding set permission_version=permission_version+1,version=version+1,updated_at=:now,updated_by=:actor
                 where catalog_scope_id=:scope and role_id=:role and enabled and permission_version=:expected
                """, Map.of("scope", Long.parseLong(scope.scope().catalogScopeId()), "role", role, "now", now, "actor", actor, "expected", expected)).executeUpdate();
        if (changed != 1) throw new Rbac3RuleViolation("RESOURCE_VERSION_CONFLICT");
        Set<String> oldCodes = previous.permissions().stream().map(RolePermissionGrantViewVO.Grant::permissionCode).collect(Collectors.toSet());
        Set<String> requested = Set.copyOf(request.permissionCodes());
        return new Mutation(Long.toString(Math.addExact(expected, 1)), requested.stream().filter(code -> !oldCodes.contains(code)).count(),
                oldCodes.stream().filter(code -> !requested.contains(code)).count());
    }

    public void requireActiveCodes(CatalogScope scope, List<String> permissionCodes) {
        activePermissionIds(scope, permissionCodes);
    }

    private List<Long> activePermissionIds(CatalogScope scope, List<String> permissionCodes) {
        if (permissionCodes.isEmpty()) return List.of();
        Set<String> codes = Set.copyOf(permissionCodes);
        List<?> rows = query("""
                select distinct p.id from rbac3_catalog_permission p
                  join rbac3_catalog_permission_version v on v.catalog_scope_id=p.catalog_scope_id and v.permission_id=p.id
                  join rbac3_catalog_activation_producer a on a.catalog_scope_id=v.catalog_scope_id and a.producer_id=v.producer_id and a.producer_version=v.producer_version
                  join rbac3_catalog_active_pointer head on head.catalog_scope_id=a.catalog_scope_id and head.activation_version=a.activation_version
                 where p.catalog_scope_id=:scope and p.governance_state='ACTIVE' and p.permission_code in (:codes)
                """, Map.of("codes", codes, "scope", Long.parseLong(scope.catalogScopeId()))).getResultList();
        if (rows.size() != codes.size()) throw new Rbac3RuleViolation("RESOURCE_NOT_FOUND");
        return rows.stream().map(value -> ((Number) value).longValue()).toList();
    }

    private void requireRole(PermissionCatalogScopeRepository.ScopeState scope, long role, boolean lock) {
        var rows = query("""
                select id from rbac3_role where id=:role and tenant_id=:tenant and application_id=:application and status='ACTIVE'
                """ + (lock ? " for update" : ""), Map.of("role", role, "tenant", Long.parseLong(scope.scope().tenantId()), "application", scope.applicationId())).getResultList();
        if (rows.size() != 1) throw new Rbac3RuleViolation("ROLE_APPLICATION_MISMATCH");
    }

    private Map<String, Object> base(CatalogScope scope, long role) {
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("scope", Long.parseLong(scope.catalogScopeId()));
        result.put("role", role);
        return result;
    }

    private Instant instant(Object value) {
        if (value instanceof Instant instant) return instant;
        if (value instanceof OffsetDateTime timestamp) return timestamp.toInstant();
        if (value instanceof java.sql.Timestamp timestamp) return timestamp.toInstant();
        throw new IllegalArgumentException("unsupported database time");
    }

    private Query query(String sql, Map<String, Object> values) {
        Query query = entityManager.createNativeQuery(sql);
        values.forEach(query::setParameter);
        return query;
    }
}
