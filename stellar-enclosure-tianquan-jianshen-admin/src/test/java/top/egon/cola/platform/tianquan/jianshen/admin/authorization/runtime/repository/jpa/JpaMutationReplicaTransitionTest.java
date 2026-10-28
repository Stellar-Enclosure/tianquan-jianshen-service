package top.egon.cola.platform.tianquan.jianshen.admin.authorization.runtime.repository.jpa;

import jakarta.persistence.EntityManager;
import jakarta.persistence.Query;
import java.time.Instant;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.runtime.domain.enums.AuthorizationMutationResultStatusEnum;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.runtime.domain.po.AuthorizationMutationPO;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

class JpaMutationReplicaTransitionTest {
    private static final Instant NOW = Instant.parse("2026-10-28T00:00:00Z");

    @Test
    void eachTransitionIsAConditionalPrimaryWriteAndDoesNotLockRead() {
        var entities = mock(EntityManager.class);
        var query = mock(Query.class, RETURNS_SELF);
        when(entities.createNativeQuery(anyString())).thenReturn(query);
        when(query.executeUpdate()).thenReturn(1);
        when(entities.getReference(AuthorizationMutationPO.class, 42L)).thenReturn(mock(AuthorizationMutationPO.class));
        var repository = new JpaAuthorizationMutationRepository(entities);
        var parser = new org.apache.shardingsphere.infra.parser.ShardingSphereSQLParserEngine(
                org.apache.shardingsphere.infra.spi.type.typed.TypedSPILoader.getService(
                        org.apache.shardingsphere.database.connector.core.type.DatabaseType.class, "PostgreSQL"),
                new org.apache.shardingsphere.sql.parser.engine.api.CacheOption(16, 64),
                new org.apache.shardingsphere.sql.parser.engine.api.CacheOption(16, 64));

        for (var status : AuthorizationMutationResultStatusEnum.values()) {
            repository.transition("42", status, "TRANSIENT_FAILURE", NOW);
        }

        var captured = org.mockito.ArgumentCaptor.forClass(String.class);
        verify(entities, times(AuthorizationMutationResultStatusEnum.values().length)).createNativeQuery(captured.capture());
        for (String sql : captured.getAllValues()) {
            assertThat(sql.toLowerCase(java.util.Locale.ROOT)).startsWith("update rbac3_authorization_mutation")
                    .contains("mutation_id = :id", "version = version + 1").doesNotContain("for update", "for share");
            assertThat(parser.parse(sql.replaceAll(":\\w+", "?"), false)).isNotNull();
        }
        assertThat(captured.getAllValues()).anySatisfy(sql -> assertThat(sql)
                .contains("status = 'COMMITTED'").contains("status IN ('PREPARING', 'COMMITTED')"));
        assertThat(captured.getAllValues()).anySatisfy(sql -> assertThat(sql)
                .contains("status = 'RECOVERY_REQUIRED'").contains("status <> 'COMPLETED'"));
        assertThat(captured.getAllValues()).anySatisfy(sql -> assertThat(sql)
                .contains("status = 'COMPLETED'").contains("status = 'PROJECTED'"));
        verify(entities, never()).find(eq(AuthorizationMutationPO.class), any(), any(jakarta.persistence.LockModeType.class));
        verify(entities, times(AuthorizationMutationResultStatusEnum.values().length)).flush();
    }

    @Test
    void missingOrUnexpectedStateFailsWithoutReportingSuccess() {
        var entities = mock(EntityManager.class);
        var query = mock(Query.class, RETURNS_SELF);
        when(entities.createNativeQuery(anyString())).thenReturn(query);
        when(query.executeUpdate()).thenReturn(0);
        var repository = new JpaAuthorizationMutationRepository(entities);

        assertThatThrownBy(() -> repository.transition("42", AuthorizationMutationResultStatusEnum.PROJECTED, null, NOW))
                .isInstanceOf(IllegalStateException.class).hasMessageContaining("state changed");
        verify(entities, never()).getReference(any(), any());
    }

    @Test
    void failedTransitionRollsBackItsOwningTransaction() {
        var entities = mock(EntityManager.class);
        var query = mock(Query.class, RETURNS_SELF);
        when(entities.createNativeQuery(anyString())).thenReturn(query);
        when(query.executeUpdate()).thenThrow(new jakarta.persistence.PersistenceException("write failed"));
        var transactions = mock(org.springframework.transaction.PlatformTransactionManager.class);
        when(transactions.getTransaction(any())).thenReturn(new org.springframework.transaction.support.SimpleTransactionStatus());
        var transaction = new org.springframework.transaction.support.TransactionTemplate(transactions);
        var repository = new JpaAuthorizationMutationRepository(entities);

        assertThatThrownBy(() -> transaction.executeWithoutResult(status ->
                repository.transition("42", AuthorizationMutationResultStatusEnum.PROJECTED, null, NOW)))
                .isInstanceOf(jakarta.persistence.PersistenceException.class);
        verify(transactions).rollback(any());
        verify(entities, never()).getReference(any(), any());
    }

    @Test
    void lateFailureCannotUndoConcurrentCompletion() throws Exception {
        var entities = mock(EntityManager.class);
        var state = new AtomicReference<>("RECOVERY_REQUIRED");
        when(entities.getReference(AuthorizationMutationPO.class, 42L)).thenReturn(mock(AuthorizationMutationPO.class));
        when(entities.createNativeQuery(anyString())).thenAnswer(call -> {
            String sql = call.getArgument(0);
            var query = mock(Query.class, RETURNS_SELF);
            when(query.executeUpdate()).thenAnswer(ignored -> {
                synchronized (state) {
                    if (sql.contains("set projected_at")) {
                        if ("COMPLETED".equals(state.get())) return 0;
                        state.set("COMPLETED"); return 1;
                    }
                    if (sql.contains("set status = 'RECOVERY_REQUIRED'")) {
                        if ("COMPLETED".equals(state.get())) return 0;
                        state.set("RECOVERY_REQUIRED"); return 1;
                    }
                    if (sql.contains("set version = version")) return "COMPLETED".equals(state.get()) ? 1 : 0;
                    throw new AssertionError(sql);
                }
            });
            return query;
        });
        var repository = new JpaAuthorizationMutationRepository(entities);
        var start = new CountDownLatch(1);
        try (var workers = Executors.newFixedThreadPool(2)) {
            var first = workers.submit(() -> { start.await(); repository.completed("42", NOW, "worker"); return true; });
            var second = workers.submit(() -> { start.await(); repository.failed("42", "RETRY", NOW, "worker"); return true; });
            start.countDown();
            assertThat(first.get(10, TimeUnit.SECONDS)).isTrue();
            assertThat(second.get(10, TimeUnit.SECONDS)).isTrue();
        }
        assertThat(state.get()).isEqualTo("COMPLETED");
    }
}
