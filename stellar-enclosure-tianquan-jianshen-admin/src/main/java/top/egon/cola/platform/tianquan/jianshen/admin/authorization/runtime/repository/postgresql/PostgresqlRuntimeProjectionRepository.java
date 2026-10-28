package top.egon.cola.platform.tianquan.jianshen.admin.authorization.runtime.repository.postgresql;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.persistence.EntityManager;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionSynchronization;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.CanonicalJson;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

/** SQL projection storage. Replica candidates are fenced by a primary conditional write. */
@Repository
public class PostgresqlRuntimeProjectionRepository {
    private final EntityManager entityManager;
    private final ObjectMapper mapper;

    public PostgresqlRuntimeProjectionRepository(EntityManager entityManager, ObjectMapper mapper) {
        this.entityManager = Objects.requireNonNull(entityManager, "entityManager");
        this.mapper = Objects.requireNonNull(mapper, "mapper").copy()
                .disable(com.fasterxml.jackson.databind.SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);
    }

    @Transactional
    public Projection lock(String kind, String key, String tenantId) {
        TransactionState state = transactionState();
        ProjectionKey projectionKey = new ProjectionKey(kind, key, tenantId);
        Projection existing = state.rows.get(projectionKey);
        if (existing != null) return existing;
        Optional<Projection> candidate = read(kind, key, tenantId);
        if (candidate.isEmpty()) {
            int inserted = entityManager.createNativeQuery("""
                insert into rbac3_catalog_runtime_projection
                  (projection_kind, projection_key, tenant_id, payload_json, checksum, updated_at)
                values (:kind, :key, :tenant, cast(:payload as jsonb), :checksum, current_timestamp)
                on conflict (projection_kind, projection_key) do nothing
                """).setParameter("kind", kind).setParameter("key", key).setParameter("tenant", Long.valueOf(tenantId))
                    .setParameter("payload", "{}").setParameter("checksum", CanonicalJson.digest(Map.of())).executeUpdate();
            if (inserted != 1) throw new org.springframework.dao.OptimisticLockingFailureException("authorization projection is not yet visible");
            Projection created = new Projection(0, 0, Map.of(), false);
            state.rows.put(projectionKey, created);
            return created;
        }
        Projection observed = candidate.orElseThrow();
        int fenced = entityManager.createNativeQuery("""
                update rbac3_catalog_runtime_projection set updated_at = updated_at
                 where projection_kind = :kind and projection_key = :key and tenant_id = :tenant
                   and auth_version = :auth and policy_version = :policy and ready = :ready and checksum = :checksum
                """).setParameter("kind", kind).setParameter("key", key).setParameter("tenant", Long.valueOf(tenantId))
                .setParameter("auth", observed.authVersion()).setParameter("policy", observed.policyVersion())
                .setParameter("ready", observed.ready()).setParameter("checksum", CanonicalJson.digest(observed.payload()))
                .executeUpdate();
        if (fenced != 1) throw new org.springframework.dao.OptimisticLockingFailureException("authorization projection changed after replica read");
        state.rows.put(projectionKey, observed);
        return observed;
    }

    @Transactional(readOnly = true)
    public Optional<Projection> read(String kind, String key, String tenantId) {
        TransactionState state = (TransactionState) TransactionSynchronizationManager.getResource(this);
        Projection local = state == null ? null : state.rows.get(new ProjectionKey(kind, key, tenantId));
        if (local != null) return Optional.of(local);
        @SuppressWarnings("unchecked")
        List<Object[]> rows = entityManager.createNativeQuery("""
                select tenant_id, auth_version, policy_version, cast(payload_json as text), checksum, ready
                  from rbac3_catalog_runtime_projection where tenant_id = :tenant and projection_kind = :kind and projection_key = :key
                """)
                .setParameter("tenant", Long.valueOf(tenantId)).setParameter("kind", kind).setParameter("key", key).getResultList();
        if (rows.isEmpty()) return Optional.empty();
        Object[] row = rows.getFirst();
        if (!tenantId.equals(row[0].toString())) throw new IllegalStateException("AUTH_RUNTIME_IDENTITY_MISMATCH");
        Map<String, Object> payload = decode(row[3].toString(), Map.class);
        if (!CanonicalJson.digest(payload).equals(row[4].toString().trim())) {
            throw new IllegalStateException("AUTH_RUNTIME_CHECKSUM_MISMATCH");
        }
        return Optional.of(new Projection(((Number) row[1]).longValue(), ((Number) row[2]).longValue(),
                payload, Boolean.TRUE.equals(row[5])));
    }

    @Transactional
    public void save(String kind, String key, String tenantId, long authVersion, long policyVersion,
                     Object payload, boolean ready, Instant now) {
        @SuppressWarnings("unchecked")
        Map<String, Object> values = (Map<String, Object>) safeNumbers(mapper.convertValue(payload, Map.class));
        int changed = entityManager.createNativeQuery("""
                update rbac3_catalog_runtime_projection set auth_version = :auth, policy_version = :policy,
                  payload_json = cast(:payload as jsonb), checksum = :checksum, ready = :ready, updated_at = :now
                where projection_kind = :kind and projection_key = :key and tenant_id = :tenant
                """).setParameter("auth", authVersion).setParameter("policy", policyVersion)
                .setParameter("payload", CanonicalJson.write(values)).setParameter("checksum", CanonicalJson.digest(values))
                .setParameter("ready", ready).setParameter("now", now).setParameter("kind", kind)
                .setParameter("key", key).setParameter("tenant", Long.valueOf(tenantId)).executeUpdate();
        if (changed != 1) throw new IllegalStateException("AUTH_RUNTIME_PUBLICATION_CONFLICT");
        TransactionState state = (TransactionState) TransactionSynchronizationManager.getResource(this);
        if (state != null) state.rows.put(new ProjectionKey(kind, key, tenantId),
                new Projection(authVersion, policyVersion, values, ready));
    }

    private TransactionState transactionState() {
        TransactionState existing = (TransactionState) TransactionSynchronizationManager.getResource(this);
        if (existing != null) return existing;
        if (!TransactionSynchronizationManager.isActualTransactionActive()
                || !TransactionSynchronizationManager.isSynchronizationActive()) {
            throw new IllegalStateException("AUTH_RUNTIME_TRANSACTION_REQUIRED");
        }
        TransactionState state = new TransactionState();
        TransactionSynchronizationManager.bindResource(this, state);
        TransactionSynchronizationManager.registerSynchronization(new TransactionSynchronization() {
            @Override public void suspend() { TransactionSynchronizationManager.unbindResource(PostgresqlRuntimeProjectionRepository.this); }
            @Override public void resume() { TransactionSynchronizationManager.bindResource(PostgresqlRuntimeProjectionRepository.this, state); }
            @Override public void savepoint(Object savepoint) { state.savepoints.put(savepoint, new java.util.HashMap<>(state.rows)); }
            @Override public void savepointRollback(Object savepoint) {
                Map<ProjectionKey, Projection> snapshot = state.savepoints.remove(savepoint);
                state.rows.clear();
                if (snapshot != null) state.rows.putAll(snapshot);
            }
            @Override public void afterCompletion(int status) {
                TransactionSynchronizationManager.unbindResourceIfPossible(PostgresqlRuntimeProjectionRepository.this);
            }
        });
        return state;
    }

    private record ProjectionKey(String kind, String key, String tenant) { }
    private static final class TransactionState {
        private final Map<ProjectionKey, Projection> rows = new java.util.HashMap<>();
        private final Map<Object, Map<ProjectionKey, Projection>> savepoints = new java.util.IdentityHashMap<>();
    }

    private static Object safeNumbers(Object value) {
        if (value instanceof Long number && (number > 9_007_199_254_740_991L || number < -9_007_199_254_740_991L)) return number.toString();
        if (value instanceof Map<?, ?> values) {
            var result = new java.util.LinkedHashMap<String, Object>();
            values.forEach((key, item) -> result.put((String) key, safeNumbers(item)));
            return result;
        }
        if (value instanceof List<?> values) return values.stream().map(PostgresqlRuntimeProjectionRepository::safeNumbers).toList();
        return value;
    }

    public <T> T convert(Object value, Class<T> type) { return mapper.convertValue(value, type); }

    private <T> T decode(String json, Class<T> type) {
        try { return mapper.readValue(json, type); }
        catch (com.fasterxml.jackson.core.JsonProcessingException invalid) {
            throw new IllegalStateException("AUTH_RUNTIME_PAYLOAD_INVALID", invalid);
        }
    }

    public record Projection(long authVersion, long policyVersion, Map<String, Object> payload, boolean ready) { }
}
