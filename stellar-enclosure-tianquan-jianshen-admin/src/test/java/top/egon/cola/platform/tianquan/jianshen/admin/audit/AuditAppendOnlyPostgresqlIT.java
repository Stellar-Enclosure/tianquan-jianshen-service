package top.egon.cola.platform.tianquan.jianshen.admin.audit;

import jakarta.persistence.EntityManager;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.sql.Statement;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Properties;
import java.util.UUID;
import org.flywaydb.core.Flyway;
import org.hibernate.resource.jdbc.spi.StatementInspector;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.springframework.orm.jpa.LocalContainerEntityManagerFactoryBean;
import org.springframework.orm.jpa.vendor.HibernateJpaVendorAdapter;
import org.springframework.test.util.ReflectionTestUtils;
import top.egon.cola.component.common.id.snowflake.SnowflakeIdGenerator;
import top.egon.cola.platform.tianquan.jianshen.admin.audit.domain.po.AuditLogPO;
import top.egon.cola.platform.tianquan.jianshen.admin.audit.domain.vo.AuditVO;
import top.egon.cola.platform.tianquan.jianshen.admin.audit.repository.internal.AuditCursorCodec;
import top.egon.cola.platform.tianquan.jianshen.admin.audit.repository.jdbc.PostgresqlAuditRepository;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;

/** Uses the real append-only trigger in an owned random schema of the explicit PostgreSQL test database. */
class AuditAppendOnlyPostgresqlIT {
    @Test
    void numericJsonAuditInsertsFlushesAndReloadsWithoutUpdatingTheAppendOnlyFact() throws Exception {
        String url = required("TIANQUAN_JIANSHEN_IT_POSTGRES_URL");
        String user = required("TIANQUAN_JIANSHEN_IT_POSTGRES_USER");
        String password = Files.readString(Path.of(required("TIANQUAN_JIANSHEN_IT_POSTGRES_PASSWORD_FILE"))).strip();
        if (!url.startsWith("jdbc:postgresql:") || url.matches("(?is).*[?&](?:password|user)=.*")) {
            throw new IllegalArgumentException("Explicit PostgreSQL URL required");
        }
        String schema = "rbac3_audit_it_" + UUID.randomUUID().toString().replace("-", "");
        LocalContainerEntityManagerFactoryBean factory = null;
        EntityManager em = null;
        try (var connection = DriverManager.getConnection(url, user, password); var statement = connection.createStatement()) {
            statement.execute("create schema " + schema);
            try {
                Flyway.configure().dataSource(url, user, password).defaultSchema(schema).schemas(schema)
                        .table("flyway_schema_history_rbac3").locations("classpath:db/migration")
                        .initSql("SET rbac3.bootstrap.tenant_ids = '10'; SET rbac3.bootstrap.identity_sub = '9001'").load().migrate();
                var dataSource = new DriverManagerDataSource(url, user, password);
                var properties = new Properties();
                properties.setProperty("currentSchema", schema);
                dataSource.setConnectionProperties(properties);
                var sql = new ArrayList<String>();
                StatementInspector inspector = text -> {
                    sql.add(text);
                    return text;
                };
                factory = new LocalContainerEntityManagerFactoryBean();
                factory.setDataSource(dataSource);
                factory.setJpaVendorAdapter(new HibernateJpaVendorAdapter());
                factory.setPackagesToScan("top.egon.cola.platform.tianquan.jianshen.admin.audit.domain.po");
                factory.setJpaPropertyMap(Map.of("hibernate.hbm2ddl.auto", "none", "hibernate.default_schema", schema,
                        "hibernate.show_sql", false, "hibernate.session_factory.statement_inspector", inspector));
                factory.afterPropertiesSet();
                em = factory.getObject().createEntityManager();
                SnowflakeIdGenerator.initialize(0L, Duration.ofMillis(5));
                var before = Map.<String, Object>of("roleId", "51", "version", 0L, "displayPriority", 0,
                        "metadata", Map.of("privileged", false, "limits", List.of(1L, 2L)));
                var after = Map.<String, Object>of("roleId", "51", "version", 1L, "displayPriority", 1,
                        "metadata", Map.of("privileged", false, "limits", List.of(1L, 2L)));
                var candidate = new AuditVO(null, "10", "ROLE_UPDATED", "SUCCESS", "INFO", "USER",
                        "9001", "ROLE", "51", null, "ALLOW", "request-audit-append", "trace-audit-append",
                        before, after, "sha256:append-evidence", Instant.parse("2026-11-22T00:00:00Z"));
                em.getTransaction().begin();
                var persisted = new PostgresqlAuditRepository(em, mock(AuditCursorCodec.class)).append(candidate);
                em.flush();
                em.flush();
                em.getTransaction().commit();
                em.clear();
                long id = Long.parseLong(persisted.id());
                em.getTransaction().begin();
                var loaded = em.find(AuditLogPO.class, id);
                assertNotNull(loaded);
                assertEquals(1L, ((Number) loaded.getAfterSnapshot().get("version")).longValue());
                loaded.getAfterSnapshot().put("version", 99L);
                ReflectionTestUtils.setField(loaded, "reasonCode", "ACCIDENTAL_DIRTY_STATE");
                em.flush();
                em.getTransaction().commit();
                em.clear();
                var actual = em.find(AuditLogPO.class, id);
                assertEquals("ALLOW", actual.getReasonCode());
                assertEquals(1L, ((Number) actual.getAfterSnapshot().get("version")).longValue());
                assertEquals("sha256:append-evidence", actual.getPayloadChecksum());
                var statements = sql.stream().map(text -> text.toLowerCase(Locale.ROOT)).toList();
                assertEquals(1L, statements.stream()
                        .filter(text -> text.startsWith("insert into ") && text.contains("rbac3_audit_log"))
                        .count());
                assertTrue(statements.stream().noneMatch(text -> text.startsWith("update ") || text.startsWith("delete ")),
                        "Hibernate must not mutate an append-only audit fact");
                assertDatabaseRejectsChange(statement,
                        "update " + schema + ".rbac3_audit_log set reason_code='FORBIDDEN' where id=" + id);
                assertDatabaseRejectsChange(statement,
                        "delete from " + schema + ".rbac3_audit_log where id=" + id);
            } finally {
                if (em != null) {
                    if (em.getTransaction().isActive()) {
                        em.getTransaction().rollback();
                    }
                    em.close();
                }
                if (factory != null) {
                    factory.destroy();
                }
                statement.execute("drop schema " + schema + " cascade");
            }
        }
    }

    private static void assertDatabaseRejectsChange(Statement statement, String sql) {
        SQLException rejected = assertThrows(SQLException.class, () -> statement.executeUpdate(sql));
        assertEquals("55000", rejected.getSQLState());
    }

    private static String required(String name) {
        String value = System.getenv(name);
        if (value == null || value.isBlank()) {
            throw new IllegalStateException(name + " required for explicit PostgreSQL test");
        }
        return value.strip();
    }
}
