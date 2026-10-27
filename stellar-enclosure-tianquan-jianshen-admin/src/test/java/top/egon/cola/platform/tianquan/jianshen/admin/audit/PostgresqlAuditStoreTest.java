package top.egon.cola.platform.tianquan.jianshen.admin.audit;

import jakarta.persistence.EntityManager;
import jakarta.persistence.TypedQuery;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import top.egon.cola.component.common.id.snowflake.SnowflakeIdGenerator;
import top.egon.cola.platform.tianquan.jianshen.admin.audit.domain.po.AuditLogPO;
import top.egon.cola.platform.tianquan.jianshen.admin.audit.domain.vo.AuditVO;
import top.egon.cola.platform.tianquan.jianshen.admin.audit.domain.dto.QueryDTO;
import top.egon.cola.platform.tianquan.jianshen.admin.audit.repository.internal.AuditCursorCodec;
import top.egon.cola.platform.tianquan.jianshen.admin.audit.repository.jdbc.PostgresqlAuditRepository;

import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.mockito.Mockito.RETURNS_SELF;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;

class PostgresqlAuditStoreTest {

    @BeforeAll
    static void bindTheProcessWideEngine() {
        SnowflakeIdGenerator.initialize(0L, Duration.ofMillis(5));
    }

    @Test
    void returnsTheSameStableIdThatWasPersisted() {
        EntityManager entityManager = mock(EntityManager.class);
        PostgresqlAuditRepository store = new PostgresqlAuditRepository(
                entityManager, mock(AuditCursorCodec.class));
        AuditVO candidate = new AuditVO(
                null, "17", "ROLE_CHANGED", "SUCCESS", "INFO", "USER",
                "31", "ROLE", "51", null, "ALLOW", "request-1", "trace-1",
                Map.of(), Map.of("status", "ACTIVE"), "sha256:evidence",
                Instant.parse("2026-07-30T12:00:00Z"));

        AuditVO persisted = store.append(candidate);

        ArgumentCaptor<AuditLogPO> entity = ArgumentCaptor.forClass(
                AuditLogPO.class);
        verify(entityManager).persist(entity.capture());
        long generatedId = entity.getValue().getId();
        assertThat(generatedId).isPositive();
        assertThat(persisted.id()).isEqualTo(String.valueOf(generatedId));
    }

    @Test
    @SuppressWarnings("unchecked")
    void decisionLookupIncludesTheEffectiveTenantAndExactRequestId() {
        EntityManager em = mock(EntityManager.class);
        TypedQuery<AuditLogPO> query = mock(TypedQuery.class, RETURNS_SELF);
        when(em.createQuery(anyString(), eq(AuditLogPO.class))).thenReturn(query);
        when(query.getResultList()).thenReturn(List.of());
        var repository = new PostgresqlAuditRepository(em, mock(AuditCursorCodec.class));
        var now = Instant.parse("2026-10-25T00:00:00Z");
        repository.query(new QueryDTO("20", now.minusSeconds(60), now, null, null, null,
                null, null, "decision-1", null, null, 50, null));
        var sql = ArgumentCaptor.forClass(String.class);
        verify(em).createQuery(sql.capture(), eq(AuditLogPO.class));
        assertThat(sql.getValue()).contains("a.tenantId = :tenantId", "a.requestId = :requestId");
        verify(query).setParameter("tenantId", 20L);
        verify(query).setParameter("requestId", "decision-1");
    }
}
