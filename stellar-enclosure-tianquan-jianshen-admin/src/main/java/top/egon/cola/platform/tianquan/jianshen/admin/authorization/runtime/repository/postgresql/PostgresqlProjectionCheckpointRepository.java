package top.egon.cola.platform.tianquan.jianshen.admin.authorization.runtime.repository.postgresql;

import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.runtime.repository.ProjectionCheckpointRepository;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.runtime.domain.enums.RuntimeSnapshotRebuildClaimEnum;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.CanonicalJson;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.UUID;

/** Token-fenced SQL claims prevent an expired worker from completing a successor's delivery. */
@Repository
@Transactional
public class PostgresqlProjectionCheckpointRepository implements ProjectionCheckpointRepository {
    private final PostgresqlRuntimeProjectionRepository projections;
    private final Clock clock;

    public PostgresqlProjectionCheckpointRepository(PostgresqlRuntimeProjectionRepository projections, Clock clock) {
        this.projections = projections;
        this.clock = clock;
    }

    @Override
    public Claim claimOwned(String tenant, String event, String type, String aggregate, long version) {
        String key = key(tenant, type, aggregate);
        var current = projections.lock("CHECKPOINT", key, tenant);
        Map<String, Object> payload = current.payload();
        if (!payload.isEmpty()) {
            long applied = Long.parseLong(payload.get("aggregateVersion").toString());
            if (applied > version) return new Claim(RuntimeSnapshotRebuildClaimEnum.STALE, null);
            if (current.ready() && applied == version) return new Claim(RuntimeSnapshotRebuildClaimEnum.ALREADY_APPLIED, null);
            if (!current.ready() && Instant.parse(payload.get("leaseUntil").toString()).isAfter(clock.instant())) {
                return new Claim(RuntimeSnapshotRebuildClaimEnum.BUSY, null);
            }
        }
        String token = UUID.randomUUID().toString();
        projections.save("CHECKPOINT", key, tenant, 0, 0,
                Map.of("eventId", event, "aggregateVersion", Long.toString(version), "leaseToken", token,
                        "leaseUntil", clock.instant().plus(Duration.ofMinutes(5)).toString()), false, clock.instant());
        return new Claim(RuntimeSnapshotRebuildClaimEnum.ACQUIRED, token);
    }

    @Override
    public void completeOwned(String tenant, String event, String type, String aggregate, long version, String token) {
        String key = key(tenant, type, aggregate);
        var current = projections.lock("CHECKPOINT", key, tenant);
        requireOwner(current, event, version, token);
        projections.save("CHECKPOINT", key, tenant, 0, 0,
                Map.of("eventId", event, "aggregateVersion", Long.toString(version)), true, clock.instant());
    }

    @Override
    public void releaseOwned(String tenant, String event, String type, String aggregate, long version, String token) {
        String key = key(tenant, type, aggregate);
        var current = projections.lock("CHECKPOINT", key, tenant);
        if (current.ready() || !token.equals(current.payload().get("leaseToken"))) return;
        projections.save("CHECKPOINT", key, tenant, 0, 0,
                Map.of("eventId", event, "aggregateVersion", Long.toString(version), "leaseToken", token,
                        "leaseUntil", clock.instant().toString()), false, clock.instant());
    }

    private void requireOwner(PostgresqlRuntimeProjectionRepository.Projection current, String event, long version, String token) {
        if (current.ready() || token == null || !token.equals(current.payload().get("leaseToken"))
                || !event.equals(current.payload().get("eventId"))
                || Long.parseLong(current.payload().get("aggregateVersion").toString()) != version
                || !Instant.parse(current.payload().get("leaseUntil").toString()).isAfter(clock.instant())) {
            throw new IllegalStateException("AUTH_PROJECTION_CLAIM_LOST");
        }
    }

    private static String key(String tenant, String type, String aggregate) {
        return tenant + ':' + CanonicalJson.digest(Map.of("type", type, "aggregate", aggregate));
    }

    @Override public RuntimeSnapshotRebuildClaimEnum claim(String t, String e, String a, String i, long v) {
        throw new IllegalStateException("SQL_PROJECTION_CLAIM_TOKEN_REQUIRED");
    }
    @Override public void complete(String t, String e, String a, String i, long v) {
        throw new IllegalStateException("SQL_PROJECTION_CLAIM_TOKEN_REQUIRED");
    }
    @Override public void release(String t, String e, String a, String i, long v) {
        throw new IllegalStateException("SQL_PROJECTION_CLAIM_TOKEN_REQUIRED");
    }
}
