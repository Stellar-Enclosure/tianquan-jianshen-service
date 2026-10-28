package top.egon.cola.platform.tianquan.jianshen.admin.authorization.runtime.repository.postgresql;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import jakarta.persistence.EntityManager;
import jakarta.persistence.Query;
import org.junit.jupiter.api.Test;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.CanonicalJson;
import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import static org.assertj.core.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

class PostgresqlRuntimeProjectionRepositoryTest {
    private static final Instant NOW = Instant.parse("2026-10-25T00:00:00.123456Z");
    private final EntityManager entityManager = mock(EntityManager.class);
    private final Query query = mock(Query.class);
    private final Map<String, Object> parameters = new HashMap<>();
    private final ObjectMapper mapper = new ObjectMapper().registerModule(new JavaTimeModule());
    private final PostgresqlRuntimeProjectionRepository repository = new PostgresqlRuntimeProjectionRepository(entityManager, mapper);

    private void configureQuery() {
        when(entityManager.createNativeQuery(anyString())).thenReturn(query);
        when(query.setParameter(anyString(), any())).thenAnswer(call -> {
            parameters.put(call.getArgument(0), call.getArgument(1)); return query;
        });
        when(query.executeUpdate()).thenReturn(1);
    }

    @Test
    void canonicalSqlPayloadPreservesNanosecondsAndVersionsAboveJavascriptPrecision() throws Exception {
        configureQuery();
        var payload = new Payload(NOW, Long.MAX_VALUE, Map.of("nested", List.of(Long.MAX_VALUE)));
        repository.save("SNAPSHOT", "subject", "10", Long.MAX_VALUE, 5L, payload, true, NOW);
        String stored = (String) parameters.get("payload");
        var json = mapper.readTree(stored);
        assertThat(json.path("generatedAt").asText()).isEqualTo(NOW.toString());
        assertThat(json.path("authVersion").asText()).isEqualTo(Long.toString(Long.MAX_VALUE));
        assertThat(json.path("details").path("nested").get(0).isTextual()).isTrue();
        assertThat(parameters.get("checksum")).isEqualTo(CanonicalJson.digestUtf8(stored));
        when(query.getResultList()).thenReturn(List.<Object[]>of(new Object[] {10L, Long.MAX_VALUE, 5L,
                stored, parameters.get("checksum"), true}));
        var restored = repository.read("SNAPSHOT", "subject", "10").orElseThrow();
        assertThat(repository.convert(restored.payload(), Payload.class)).isEqualTo(payload);
        assertThat(mapper.isEnabled(com.fasterxml.jackson.databind.SerializationFeature.WRITE_DATES_AS_TIMESTAMPS)).isTrue();
    }

    @Test
    void wrongTenantOrTamperedPayloadNeverReturnsAProjection() {
        configureQuery();
        when(query.getResultList()).thenReturn(List.<Object[]>of(new Object[] {11L, 1L, 1L, "{}", CanonicalJson.digest(Map.of()), true}));
        assertThatThrownBy(() -> repository.read("SNAPSHOT", "subject", "10")).hasMessage("AUTH_RUNTIME_IDENTITY_MISMATCH");
        when(query.getResultList()).thenReturn(List.<Object[]>of(new Object[] {10L, 1L, 1L, "{\"changed\":true}", CanonicalJson.digest(Map.of()), true}));
        assertThatThrownBy(() -> repository.read("SNAPSHOT", "subject", "10")).hasMessage("AUTH_RUNTIME_CHECKSUM_MISMATCH");
    }

    @Test
    void missingLockedRowCannotBeReportedAsPublished() {
        configureQuery();
        when(query.executeUpdate()).thenReturn(0);
        assertThatThrownBy(() -> repository.save("SNAPSHOT", "subject", "10", 1L, 1L, Map.of(), true, NOW))
                .hasMessage("AUTH_RUNTIME_PUBLICATION_CONFLICT");
    }

    @Test
    void fencedProjectionUsesReplicaCandidateAndKeepsTransactionLocalWrites() {
        configureQuery();
        when(query.getResultList()).thenReturn(List.<Object[]>of(new Object[] {10L, 1L, 2L,
                "{}", CanonicalJson.digest(Map.of()), false}));
        org.springframework.transaction.support.TransactionSynchronizationManager.initSynchronization();
        org.springframework.transaction.support.TransactionSynchronizationManager.setActualTransactionActive(true);
        try {
            var observed = repository.lock("USER", "subject", "10");
            assertThat(observed.authVersion()).isEqualTo(1L);
            var synchronization = org.springframework.transaction.support.TransactionSynchronizationManager.getSynchronizations().getFirst();
            Object savepoint = new Object();
            synchronization.savepoint(savepoint);
            repository.save("USER", "subject", "10", 3L, 4L, Map.of("ready", true), true, NOW);
            assertThat(repository.read("USER", "subject", "10")).get().extracting(
                    PostgresqlRuntimeProjectionRepository.Projection::authVersion).isEqualTo(3L);
            synchronization.savepointRollback(savepoint);
            assertThat(repository.lock("USER", "subject", "10")).isEqualTo(observed);
            synchronization.suspend();
            assertThat(org.springframework.transaction.support.TransactionSynchronizationManager.hasResource(repository)).isFalse();
            synchronization.resume();
            assertThat(repository.read("USER", "subject", "10")).contains(observed);
            // The transaction cache may have been created after an existing savepoint.
            synchronization.savepointRollback(new Object());
            assertThat(repository.lock("USER", "subject", "10")).isEqualTo(observed);
            var sql = org.mockito.ArgumentCaptor.forClass(String.class);
            verify(entityManager, atLeastOnce()).createNativeQuery(sql.capture());
            assertThat(sql.getAllValues()).allSatisfy(value -> assertThat(value.toLowerCase())
                    .doesNotContain("for update", "for share"));
            assertThat(sql.getAllValues()).anySatisfy(value -> assertThat(value)
                    .contains("auth_version = :auth", "policy_version = :policy", "checksum = :checksum"));
            synchronization.afterCompletion(org.springframework.transaction.support.TransactionSynchronization.STATUS_COMMITTED);
        } finally {
            org.springframework.transaction.support.TransactionSynchronizationManager.unbindResourceIfPossible(repository);
            org.springframework.transaction.support.TransactionSynchronizationManager.clearSynchronization();
            org.springframework.transaction.support.TransactionSynchronizationManager.setActualTransactionActive(false);
        }
    }

    @Test
    void staleReplicaProjectionFailsBeforeReturningAFencedRow() {
        configureQuery();
        when(query.getResultList()).thenReturn(List.<Object[]>of(new Object[] {10L, 1L, 2L,
                "{}", CanonicalJson.digest(Map.of()), false}));
        when(query.executeUpdate()).thenReturn(0);
        org.springframework.transaction.support.TransactionSynchronizationManager.initSynchronization();
        org.springframework.transaction.support.TransactionSynchronizationManager.setActualTransactionActive(true);
        try {
            assertThatThrownBy(() -> repository.lock("USER", "subject", "10"))
                    .isInstanceOf(org.springframework.dao.OptimisticLockingFailureException.class);
        } finally {
            org.springframework.transaction.support.TransactionSynchronizationManager.unbindResourceIfPossible(repository);
            org.springframework.transaction.support.TransactionSynchronizationManager.clearSynchronization();
            org.springframework.transaction.support.TransactionSynchronizationManager.setActualTransactionActive(false);
        }
    }

    record Payload(Instant generatedAt, long authVersion, Map<String, List<Long>> details) { }
}
