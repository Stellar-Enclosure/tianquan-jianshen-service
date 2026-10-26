package top.egon.cola.platform.tianquan.jianshen.admin.authorization.runtime.repository.postgresql;

import org.junit.jupiter.api.Test;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.runtime.domain.enums.RuntimeSnapshotRebuildClaimEnum;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;
import static org.assertj.core.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

class PostgresqlProjectionCheckpointRepositoryTest {
    private static final Instant NOW = Instant.parse("2026-10-25T00:00:00Z");
    private final PostgresqlRuntimeProjectionRepository projections = mock(PostgresqlRuntimeProjectionRepository.class);
    private final AtomicReference<PostgresqlRuntimeProjectionRepository.Projection> current = new AtomicReference<>(
            new PostgresqlRuntimeProjectionRepository.Projection(0, 0, Map.of(), false));

    @SuppressWarnings("unchecked")
    private PostgresqlProjectionCheckpointRepository repository(Instant now) {
        when(projections.lock(anyString(), anyString(), eq("10"))).thenAnswer(call -> current.get());
        doAnswer(call -> {
            current.set(new PostgresqlRuntimeProjectionRepository.Projection(0, 0,
                    (Map<String,Object>) call.getArgument(5), call.getArgument(6))); return null;
        }).when(projections).save(anyString(), anyString(), eq("10"), anyLong(), anyLong(), any(), anyBoolean(), any());
        return new PostgresqlProjectionCheckpointRepository(projections, Clock.fixed(now, ZoneOffset.UTC));
    }

    @Test
    void expiredWorkerCannotCompleteOrReleaseItsSuccessorsLease() {
        var first = repository(NOW);
        var firstClaim = first.claimOwned("10", "event", "ROLE", "20", Long.MAX_VALUE);
        assertThat(firstClaim.outcome()).isEqualTo(RuntimeSnapshotRebuildClaimEnum.ACQUIRED);
        assertThat(first.claimOwned("10", "event", "ROLE", "20", Long.MAX_VALUE).outcome()).isEqualTo(RuntimeSnapshotRebuildClaimEnum.BUSY);
        var next = repository(NOW.plusSeconds(301));
        var nextClaim = next.claimOwned("10", "event", "ROLE", "20", Long.MAX_VALUE);
        assertThat(nextClaim.leaseToken()).isNotEqualTo(firstClaim.leaseToken());
        assertThatThrownBy(() -> next.completeOwned("10", "event", "ROLE", "20", Long.MAX_VALUE, firstClaim.leaseToken()))
                .hasMessage("AUTH_PROJECTION_CLAIM_LOST");
        next.releaseOwned("10", "event", "ROLE", "20", Long.MAX_VALUE, firstClaim.leaseToken());
        assertThat(current.get().payload().get("leaseToken")).isEqualTo(nextClaim.leaseToken());
        next.completeOwned("10", "event", "ROLE", "20", Long.MAX_VALUE, nextClaim.leaseToken());
        assertThat(next.claimOwned("10", "event", "ROLE", "20", Long.MAX_VALUE).outcome()).isEqualTo(RuntimeSnapshotRebuildClaimEnum.ALREADY_APPLIED);
        assertThat(next.claimOwned("10", "old", "ROLE", "20", Long.MAX_VALUE - 1).outcome()).isEqualTo(RuntimeSnapshotRebuildClaimEnum.STALE);
    }

    @Test
    void expiryAloneRevokesCompletionEvenWithoutASuccessor() {
        var active = repository(NOW);
        var claim = active.claimOwned("10", "event", "ROLE", "20", 2L);
        var expired = repository(NOW.plusSeconds(300));
        assertThatThrownBy(() -> expired.completeOwned("10", "event", "ROLE", "20", 2L, claim.leaseToken()))
                .hasMessage("AUTH_PROJECTION_CLAIM_LOST");
        assertThat(current.get().ready()).isFalse();
    }
}
