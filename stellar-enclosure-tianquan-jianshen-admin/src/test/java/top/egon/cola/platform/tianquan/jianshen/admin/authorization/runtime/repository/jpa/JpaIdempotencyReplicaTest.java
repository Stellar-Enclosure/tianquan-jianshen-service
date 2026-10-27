package top.egon.cola.platform.tianquan.jianshen.admin.authorization.runtime.repository.jpa;

import jakarta.persistence.EntityManager;
import jakarta.persistence.Query;
import jakarta.persistence.TypedQuery;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import org.junit.jupiter.api.Test;
import top.egon.cola.component.common.id.snowflake.SnowflakeIdGenerator;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.runtime.domain.dto.StoredCommandDTO;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.runtime.domain.enums.IdempotencyOutcomeEnum;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.runtime.domain.po.IdempotencyRecordPO;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

class JpaIdempotencyReplicaTest {
    private static final Instant NOW = Instant.parse("2026-10-28T00:00:00Z");

    @Test
    void absentReplicaCandidateIsInsertedAndFlushedWithoutALockingRead() {
        SnowflakeIdGenerator.initialize(0L, Duration.ofMillis(5));
        var entities = mock(EntityManager.class);
        @SuppressWarnings("unchecked")
        TypedQuery<IdempotencyRecordPO> query = mock(TypedQuery.class, RETURNS_SELF);
        when(entities.createQuery(anyString(), eq(IdempotencyRecordPO.class))).thenReturn(query);
        when(query.getResultList()).thenReturn(List.of());
        var repository = new JpaIdempotencyRepository(entities);
        var command = new StoredCommandDTO("7", "USER", "user", "CREATE", "key-hash", "request-hash", NOW.plusSeconds(60), NOW);

        assertThat(repository.claim(command).outcome()).isEqualTo(IdempotencyOutcomeEnum.CLAIMED);

        verify(query, never()).setLockMode(any());
        verify(entities).persist(any(IdempotencyRecordPO.class));
        verify(entities).flush();
    }

    @Test
    void completeUsesOnePrimaryConditionalWriteAndRejectsDuplicateCompletion() {
        var entities = mock(EntityManager.class);
        var update = mock(Query.class, RETURNS_SELF);
        var reference = mock(IdempotencyRecordPO.class);
        when(entities.createNativeQuery(anyString())).thenReturn(update);
        when(update.executeUpdate()).thenReturn(1, 0);
        when(entities.getReference(IdempotencyRecordPO.class, 42L)).thenReturn(reference);
        var repository = new JpaIdempotencyRepository(entities);

        repository.complete("42", "ROLE", "9", 200, "digest", NOW);
        assertThatThrownBy(() -> repository.complete("42", "ROLE", "9", 200, "digest", NOW))
                .isInstanceOf(IllegalStateException.class).hasMessageContaining("already completed");

        var sql = org.mockito.ArgumentCaptor.forClass(String.class);
        verify(entities, times(2)).createNativeQuery(sql.capture());
        assertThat(sql.getAllValues()).allSatisfy(statement -> assertThat(statement.toLowerCase(java.util.Locale.ROOT))
                .contains("update rbac3_idempotency_record", "version = version + 1", "id = :id", "status = 'processing'"));
        verify(entities, never()).find(eq(IdempotencyRecordPO.class), any(), any(jakarta.persistence.LockModeType.class));
        verify(entities).detach(reference);
    }

    @Test
    void aUniqueConflictDuringClaimDoesNotReportSuccess() {
        SnowflakeIdGenerator.initialize(0L, Duration.ofMillis(5));
        var entities = mock(EntityManager.class);
        @SuppressWarnings("unchecked")
        TypedQuery<IdempotencyRecordPO> query = mock(TypedQuery.class, RETURNS_SELF);
        when(entities.createQuery(anyString(), eq(IdempotencyRecordPO.class))).thenReturn(query);
        when(query.getResultList()).thenReturn(List.of());
        doThrow(new jakarta.persistence.PersistenceException("unique conflict")).when(entities).flush();
        var repository = new JpaIdempotencyRepository(entities);
        var command = new StoredCommandDTO("7", "USER", "user", "CREATE", "key-hash", "request-hash", NOW.plusSeconds(60), NOW);

        assertThatThrownBy(() -> repository.claim(command)).isInstanceOf(jakarta.persistence.PersistenceException.class);
    }
}
