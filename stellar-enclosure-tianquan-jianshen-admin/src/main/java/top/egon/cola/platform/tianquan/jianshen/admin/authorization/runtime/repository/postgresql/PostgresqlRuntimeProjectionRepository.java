package top.egon.cola.platform.tianquan.jianshen.admin.authorization.runtime.repository.postgresql;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.persistence.EntityManager;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.CanonicalJson;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

/** SQL projection storage. Row locks and checksum verification belong to the caller's local transaction. */
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
        String empty = "{}";
        entityManager.createNativeQuery("""
                insert into rbac3_catalog_runtime_projection
                  (projection_kind, projection_key, tenant_id, payload_json, checksum, updated_at)
                values (:kind, :key, :tenant, cast(:payload as jsonb), :checksum, current_timestamp)
                on conflict (projection_kind, projection_key) do nothing
                """).setParameter("kind", kind).setParameter("key", key).setParameter("tenant", Long.valueOf(tenantId))
                .setParameter("payload", empty).setParameter("checksum", CanonicalJson.digest(Map.of())).executeUpdate();
        return read(kind, key, tenantId, true).orElseThrow(() -> new IllegalStateException("AUTH_RUNTIME_UNAVAILABLE"));
    }

    @Transactional(readOnly = true)
    public Optional<Projection> read(String kind, String key, String tenantId) {
        return read(kind, key, tenantId, false);
    }

    private Optional<Projection> read(String kind, String key, String tenantId, boolean lock) {
        @SuppressWarnings("unchecked")
        List<Object[]> rows = entityManager.createNativeQuery("""
                select tenant_id, auth_version, policy_version, cast(payload_json as text), checksum, ready
                  from rbac3_catalog_runtime_projection where projection_kind = :kind and projection_key = :key
                """ + (lock ? " for update" : ""))
                .setParameter("kind", kind).setParameter("key", key).getResultList();
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
