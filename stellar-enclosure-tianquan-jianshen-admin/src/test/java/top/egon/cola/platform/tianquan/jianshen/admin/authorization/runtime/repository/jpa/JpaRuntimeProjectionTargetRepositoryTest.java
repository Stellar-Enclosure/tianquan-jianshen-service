package top.egon.cola.platform.tianquan.jianshen.admin.authorization.runtime.repository.jpa;

import jakarta.persistence.EntityManager;
import jakarta.persistence.Query;
import java.util.List;
import org.junit.jupiter.api.Test;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.runtime.repository.RuntimeProjectionTargetRepository.ProjectionTarget;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

class JpaRuntimeProjectionTargetRepositoryTest {
    @Test
    void primaryConditionalWritesVerifyEveryPageAndItsTail() {
        var entities = mock(EntityManager.class);
        var query = mock(Query.class, RETURNS_SELF);
        when(entities.createNativeQuery(anyString())).thenReturn(query);
        when(query.executeUpdate()).thenReturn(1);
        var repository = new JpaRuntimeProjectionTargetRepository(entities);
        var page = List.of(new ProjectionTarget("9", "alice", 1, true),
                new ProjectionTarget("15", "bob", 2, true));

        repository.beginTenantProjection("7");
        repository.requirePage("7", 2, page);
        repository.requireExhausted("7", 15);

        var sql = org.mockito.ArgumentCaptor.forClass(String.class);
        verify(entities, times(3)).createNativeQuery(sql.capture());
        assertThat(sql.getAllValues().get(1)).contains("count(*)", "u.id > :after", "u.id <= :last",
                "u.id = :id0", "u.id = :id1", "u.tenant_id = :tenant");
        assertThat(sql.getAllValues().get(2)).contains("not exists", "u.id > :after");
        verify(query).setParameter("id0", 9L);
        verify(query).setParameter("id1", 15L);
        var parser = new org.apache.shardingsphere.infra.parser.ShardingSphereSQLParserEngine(
                org.apache.shardingsphere.infra.spi.type.typed.TypedSPILoader.getService(
                        org.apache.shardingsphere.database.connector.core.type.DatabaseType.class, "PostgreSQL"),
                new org.apache.shardingsphere.sql.parser.engine.api.CacheOption(16, 64),
                new org.apache.shardingsphere.sql.parser.engine.api.CacheOption(16, 64));
        assertThat(sql.getAllValues()).allSatisfy(value -> {
            assertThat(value.toLowerCase()).doesNotContain("for update", "for share");
            assertThat(parser.parse(value.replaceAll(":\\w+", "?"), false)).isNotNull();
        });
    }

    @Test
    void replicaOmissionsFailClosedAndInvalidPagesAreRejected() {
        var entities = mock(EntityManager.class);
        var query = mock(Query.class, RETURNS_SELF);
        when(entities.createNativeQuery(anyString())).thenReturn(query);
        when(query.executeUpdate()).thenReturn(0);
        var repository = new JpaRuntimeProjectionTargetRepository(entities);
        var page = List.of(new ProjectionTarget("9", "alice", 1, true));
        assertThatThrownBy(() -> repository.requirePage("7", 0, page))
                .isInstanceOf(org.springframework.dao.OptimisticLockingFailureException.class);
        assertThatThrownBy(() -> repository.requireExhausted("7", 9))
                .isInstanceOf(org.springframework.dao.OptimisticLockingFailureException.class);
        assertThatThrownBy(() -> repository.requirePage("7", 9, page))
                .isInstanceOf(IllegalArgumentException.class);
    }
}
