package top.egon.cola.platform.tianquan.jianshen.admin.authorization.runtime.repository.jpa;

import jakarta.persistence.EntityManager;
import jakarta.persistence.Query;
import jakarta.persistence.TypedQuery;
import java.time.Instant;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.runtime.domain.enums.AuthorizationMutationResultStatusEnum;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.runtime.domain.enums.AuthorizationMutationScopeTypeEnum;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.runtime.domain.enums.AuthorizationMutationStatusEnum;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.runtime.domain.po.AuthorizationMutationPO;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

class JpaMutationReplicaTransitionTest {
    private static final Instant NOW = Instant.parse("2026-10-28T00:00:00Z");

    @Test
    void committedAndClaimedTransitionsUseConditionalWrites() {
        var entities = mock(EntityManager.class);
        var query = mock(Query.class, RETURNS_SELF);
        when(entities.createNativeQuery(anyString())).thenReturn(query);
        when(query.executeUpdate()).thenReturn(1);
        when(entities.getReference(AuthorizationMutationPO.class, 42L)).thenReturn(mock(AuthorizationMutationPO.class));
        var repository = new JpaAuthorizationMutationRepository(entities);

        repository.transition("7", "42", AuthorizationMutationResultStatusEnum.COMMITTED, null, NOW);
        repository.transitionClaimed("7", "42", "owner-a", AuthorizationMutationResultStatusEnum.FENCED, NOW);
        repository.transitionClaimed("7", "42", "owner-a", AuthorizationMutationResultStatusEnum.PROJECTED, NOW);
        assertThatThrownBy(() -> repository.transition("7", "42", AuthorizationMutationResultStatusEnum.COMPLETED, null, NOW))
                .isInstanceOf(IllegalArgumentException.class);
        var sql = org.mockito.ArgumentCaptor.forClass(String.class);
        verify(entities, times(3)).createNativeQuery(sql.capture());
        assertThat(sql.getAllValues().getFirst()).contains("status = 'COMMITTED'", "tenant_id = :tenant");
        assertThat(sql.getAllValues().subList(1, 3)).allSatisfy(value -> assertThat(value)
                .contains("tenant_id = :tenant", "claim_owner = :owner", "version = version + 1")
                .doesNotContain("for update", "for share"));
    }

    @Test
    void concurrentReplicaCandidatesHaveOnlyOneDurableOwner() throws Exception {
        var entities = mock(EntityManager.class);
        @SuppressWarnings("unchecked") TypedQuery<AuthorizationMutationPO> lookup = mock(TypedQuery.class, RETURNS_SELF);
        var row = mock(AuthorizationMutationPO.class);
        when(row.getMutationId()).thenReturn(42L);
        when(row.getTenantId()).thenReturn(7L);
        when(row.getUserId()).thenReturn(9L);
        when(row.getScopeType()).thenReturn(AuthorizationMutationScopeTypeEnum.USER);
        when(row.getStatus()).thenReturn(AuthorizationMutationStatusEnum.RECOVERY_REQUIRED);
        when(row.getVersion()).thenReturn(0L);
        when(entities.createQuery(anyString(), eq(AuthorizationMutationPO.class))).thenReturn(lookup);
        when(lookup.getResultList()).thenReturn(List.of(row));
        var currentOwner = new AtomicReference<String>();
        when(entities.createNativeQuery(anyString())).thenAnswer(call -> {
            var update = mock(Query.class);
            var supplied = new java.util.concurrent.ConcurrentHashMap<String, Object>();
            when(update.setParameter(anyString(), any())).thenAnswer(parameter -> {
                supplied.put(parameter.getArgument(0), parameter.getArgument(1)); return update;
            });
            when(update.executeUpdate()).thenAnswer(ignored -> currentOwner.compareAndSet(null, (String) supplied.get("owner")) ? 1 : 0);
            return update;
        });
        var repository = new JpaAuthorizationMutationRepository(entities);
        var start = new CountDownLatch(1);
        try (var workers = Executors.newFixedThreadPool(2)) {
            var first = workers.submit(() -> claim(repository, start));
            var second = workers.submit(() -> claim(repository, start));
            start.countDown();
            var results = List.of(first.get(5, TimeUnit.SECONDS), second.get(5, TimeUnit.SECONDS));
            assertThat(results.stream().filter(Boolean::booleanValue)).hasSize(1);
            assertThat(currentOwner.get()).isNotBlank();
        }
        verify(lookup, never()).setLockMode(any());
    }

    private static boolean claim(JpaAuthorizationMutationRepository repository, CountDownLatch start) throws Exception {
        start.await();
        try {
            return repository.claimById("7", "42").orElseThrow().claimOwner() != null;
        } catch (org.springframework.dao.TransientDataAccessResourceException busy) {
            return false;
        }
    }

    @Test
    void expiredOrReplacedOwnerCannotRunOrOverwriteCompletion() {
        var entities = mock(EntityManager.class);
        var query = mock(Query.class, RETURNS_SELF);
        when(entities.createNativeQuery(anyString())).thenReturn(query);
        when(query.executeUpdate()).thenReturn(0);
        var repository = new JpaAuthorizationMutationRepository(entities);
        Runnable projection = mock(Runnable.class);

        assertThat(repository.runClaimed("7", "42", "old-owner", projection, NOW, "worker")).isFalse();
        assertThat(repository.failClaimed("7", "42", "old-owner", "RETRY", NOW, "worker")).isFalse();
        verifyNoInteractions(projection);
        var sql = org.mockito.ArgumentCaptor.forClass(String.class);
        verify(entities, times(2)).createNativeQuery(sql.capture());
        assertThat(sql.getAllValues()).allSatisfy(value -> assertThat(value)
                .contains("tenant_id = :tenant", "claim_owner = :owner"));
        assertThat(sql.getAllValues().getFirst()).contains("claim_expires_at > current_timestamp");
    }

    @Test
    void successfulProjectionCompletesAndClearsTheSameOwner() {
        var entities = mock(EntityManager.class);
        var query = mock(Query.class, RETURNS_SELF);
        when(entities.createNativeQuery(anyString())).thenReturn(query);
        when(query.executeUpdate()).thenReturn(1);
        when(entities.getReference(AuthorizationMutationPO.class, 42L)).thenReturn(mock(AuthorizationMutationPO.class));
        var repository = new JpaAuthorizationMutationRepository(entities);
        Runnable projection = mock(Runnable.class);

        assertThat(repository.runClaimed("7", "42", "owner-a", projection, NOW, "worker")).isTrue();
        verify(projection).run();
        verify(query, times(2)).setParameter("owner", "owner-a");
        var sql = org.mockito.ArgumentCaptor.forClass(String.class);
        verify(entities, times(2)).createNativeQuery(sql.capture());
        assertThat(sql.getAllValues().getLast()).contains("status = 'COMPLETED'", "claim_owner = null",
                "claim_expires_at = null", "claim_owner = :owner");
    }

    @Test
    void projectionFailureRollsBackTheClaimedTransaction() {
        var entities = mock(EntityManager.class);
        var query = mock(Query.class, RETURNS_SELF);
        when(entities.createNativeQuery(anyString())).thenReturn(query);
        when(query.executeUpdate()).thenReturn(1);
        var transactions = mock(org.springframework.transaction.PlatformTransactionManager.class);
        when(transactions.getTransaction(any())).thenReturn(new org.springframework.transaction.support.SimpleTransactionStatus());
        var transaction = new org.springframework.transaction.support.TransactionTemplate(transactions);
        var repository = new JpaAuthorizationMutationRepository(entities);

        assertThatThrownBy(() -> transaction.executeWithoutResult(status -> repository.runClaimed("7", "42", "owner",
                () -> { throw new IllegalStateException("projection failed"); }, NOW, "worker")))
                .hasMessage("projection failed");
        verify(transactions).rollback(any());
        verify(entities, times(1)).createNativeQuery(anyString());
    }

    @Test
    void initialClaimSqlParsesAndChecksTheDatabaseLease() {
        var entities = mock(EntityManager.class);
        var query = mock(Query.class, RETURNS_SELF);
        when(entities.createNativeQuery(anyString())).thenReturn(query);
        when(query.executeUpdate()).thenReturn(1);
        assertThat(new JpaAuthorizationMutationRepository(entities).claimInitial("7", "42", "owner")).isTrue();
        var sql = org.mockito.ArgumentCaptor.forClass(String.class);
        verify(entities).createNativeQuery(sql.capture());
        assertThat(sql.getValue()).contains("tenant_id = :tenant", "mutation_id = :id",
                "claim_expires_at <= current_timestamp", "interval '15 minutes'").doesNotContain("for update");
        var parser = new org.apache.shardingsphere.infra.parser.ShardingSphereSQLParserEngine(
                org.apache.shardingsphere.infra.spi.type.typed.TypedSPILoader.getService(
                        org.apache.shardingsphere.database.connector.core.type.DatabaseType.class, "PostgreSQL"),
                new org.apache.shardingsphere.sql.parser.engine.api.CacheOption(16, 64),
                new org.apache.shardingsphere.sql.parser.engine.api.CacheOption(16, 64));
        assertThat(parser.parse(sql.getValue().replaceAll(":\\w+", "?"), false)).isNotNull();
    }
}
