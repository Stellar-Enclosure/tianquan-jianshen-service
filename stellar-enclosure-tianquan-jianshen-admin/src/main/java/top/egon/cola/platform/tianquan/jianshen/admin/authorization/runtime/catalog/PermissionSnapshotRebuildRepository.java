package top.egon.cola.platform.tianquan.jianshen.admin.authorization.runtime.catalog;

import jakarta.persistence.EntityManager;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;
import top.egon.cola.component.common.id.snowflake.SnowflakeIdGenerator;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.runtime.domain.vo.EventEnvelopeVO;
import top.egon.cola.platform.tianquan.jianshen.admin.shared.domain.DatabaseClock;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/** Durable rebuild queue with version/lease CAS; no Redis lease or unsupported SKIP LOCKED SQL. */
@Repository
public class PermissionSnapshotRebuildRepository {
    private final EntityManager manager;
    private final DatabaseClock clock;

    public PermissionSnapshotRebuildRepository(EntityManager manager, DatabaseClock clock) {
        this.manager = manager; this.clock = clock;
    }

    @Transactional
    public void enqueue(EventEnvelopeVO event) {
        Instant now = clock.transactionNow();
        String selectedScope = event.payload().get("catalogScopeId");
        List<Object[]> scopes = rows("""
                select s.id as scope_id, t.policy_version, p.activation_version
                  from rbac3_catalog_scope s join rbac3_tenant_authorization_state t on t.tenant_id = s.tenant_id
                  left join rbac3_catalog_active_pointer p on p.catalog_scope_id = s.id
                 where s.tenant_id = :tenant and s.status = 'ACTIVE' order by scope_id
                """, Map.of("tenant", Long.parseLong(event.tenantId())));
        for (Object[] row : scopes) {
            if (selectedScope != null && !selectedScope.equals(row[0].toString())) continue;
            long catalog = row[2] == null ? 0L : number(row[2]);
            long policy = number(row[1]);
            if (selectedScope != null && (event.payload().containsKey("policyVersion")
                    && Long.parseLong(event.payload().get("policyVersion")) > policy
                    || event.payload().containsKey("catalogVersion") && Long.parseLong(event.payload().get("catalogVersion")) > catalog)) {
                throw new IllegalStateException("AUTH_REBUILD_EVENT_VERSION_INVALID");
            }
            manager.createNativeQuery("""
                    insert into rbac3_catalog_rebuild_task (id, catalog_scope_id, requested_policy_version,
                      requested_catalog_version, command_id, next_attempt_at, deadline, created_at, updated_at)
                    values (:id, :scope, :policy, :catalog, :command, :now, :deadline, :now, :now)
                    on conflict (catalog_scope_id, command_id) do nothing
                    """).setParameter("id", SnowflakeIdGenerator.nextLongId()).setParameter("scope", number(row[0]))
                    .setParameter("policy", policy).setParameter("catalog", catalog).setParameter("command", event.eventId())
                    .setParameter("now", now).setParameter("deadline", now.plusSeconds(600)).executeUpdate();
        }
    }

    @Transactional
    public Task claim(String owner) {
        Instant now = clock.transactionNow();
        manager.createNativeQuery("""
                update rbac3_catalog_rebuild_task set state = 'FAILED', owner = null, lease_token = null,
                  lease_until = null, failure_code = 'AUTH_REBUILD_DEADLINE_EXCEEDED', version = version + 1, updated_at = :now
                 where state in ('PENDING','RUNNING') and deadline <= :now
                """).setParameter("now", now).executeUpdate();
        for (Object[] row : rows("""
                select id, catalog_scope_id, version, lease_generation, deadline, next_attempt_at from rbac3_catalog_rebuild_task
                 where deadline > :now and ((state = 'PENDING' and next_attempt_at <= :now)
                   or (state = 'RUNNING' and lease_until <= :now)) order by next_attempt_at, id limit 50
                """, Map.of("now", now))) {
            String token = UUID.randomUUID().toString();
            Instant deadline = instant(row[4]);
            Instant lease = now.plusSeconds(60).isBefore(deadline) ? now.plusSeconds(60) : deadline;
            int changed = manager.createNativeQuery("""
                    update rbac3_catalog_rebuild_task set state = 'RUNNING', owner = :owner, lease_token = :token,
                      lease_generation = lease_generation + 1, lease_until = :lease, attempt = attempt + 1,
                      version = version + 1, updated_at = :now
                     where id = :id and version = :version and deadline > :now
                       and ((state = 'PENDING' and next_attempt_at <= :now) or (state = 'RUNNING' and lease_until <= :now))
                    """).setParameter("owner", owner).setParameter("token", token).setParameter("lease", lease)
                    .setParameter("now", now).setParameter("id", number(row[0])).setParameter("version", number(row[2])).executeUpdate();
            if (changed == 1) return new Task(number(row[0]), number(row[1]), owner, token, number(row[3]) + 1, lease);
        }
        return null;
    }

    @Transactional
    public Task renew(Task task) {
        Instant now = clock.transactionNow();
        int changed = manager.createNativeQuery("""
                update rbac3_catalog_rebuild_task set lease_until = least(:lease, deadline),
                  version = version + 1, updated_at = :now
                 where id = :id and state = 'RUNNING' and owner = :owner and lease_token = :token
                   and lease_generation = :generation and lease_until > :now and deadline > :now
                """).setParameter("lease", now.plusSeconds(60)).setParameter("now", now).setParameter("id", task.id())
                .setParameter("owner", task.owner()).setParameter("token", task.token()).setParameter("generation", task.generation()).executeUpdate();
        if (changed != 1) throw new IllegalStateException("AUTH_REBUILD_CLAIM_LOST");
        Object[] row = rows("select lease_until from rbac3_catalog_rebuild_task where id = :id", Map.of("id", task.id())).getFirst();
        return new Task(task.id(), task.scopeId(), task.owner(), task.token(), task.generation(), instant(row[0]));
    }

    @Transactional
    public void finish(Task task, boolean success) {
        Instant now = clock.transactionNow();
        int changed = manager.createNativeQuery("""
                update rbac3_catalog_rebuild_task set state = :state, owner = null, lease_token = null, lease_until = null,
                  next_attempt_at = :retry, version = version + 1, updated_at = :now
                 where id = :id and state = 'RUNNING' and owner = :owner and lease_token = :token
                   and lease_generation = :generation and lease_until > :now
                """).setParameter("state", success ? "SUCCEEDED" : "PENDING").setParameter("retry", now.plusSeconds(5))
                .setParameter("now", now).setParameter("id", task.id()).setParameter("owner", task.owner())
                .setParameter("token", task.token()).setParameter("generation", task.generation()).executeUpdate();
        if (changed != 1) throw new IllegalStateException("AUTH_REBUILD_CLAIM_LOST");
    }

    @Transactional(readOnly = true)
    public List<Long> users(String tenantId, long after) {
        return rows("select id from rbac3_user where tenant_id = :tenant and status = 'ACTIVE' and id > :after order by id limit 200",
                Map.of("tenant", Long.parseLong(tenantId), "after", after)).stream().map(row -> number(row[0])).toList();
    }

    private List<Object[]> rows(String sql, Map<String, ?> parameters) {
        var query = manager.createNativeQuery(sql); parameters.forEach(query::setParameter);
        List<?> values = query.getResultList();
        return values.stream().map(value -> value instanceof Object[] row ? row : new Object[]{value}).toList();
    }
    private static long number(Object value) { return ((Number) value).longValue(); }
    private static Instant instant(Object value) {
        if (value instanceof Instant instant) return instant;
        if (value instanceof java.time.OffsetDateTime time) return time.toInstant();
        return ((java.sql.Timestamp) value).toInstant();
    }
    public record Task(long id, long scopeId, String owner, String token, long generation, Instant leaseUntil) { }
}
