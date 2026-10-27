package top.egon.cola.platform.tianquan.jianshen.admin.config.flyway;

import net.sf.jsqlparser.parser.CCJSqlParserUtil;
import net.sf.jsqlparser.statement.select.Select;
import org.junit.jupiter.api.Test;
import top.egon.cola.component.outbox.migration.OutboxLogicalDataSourceFactory;
import top.egon.cola.component.outbox.migration.OutboxManagedDdlInitializer;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class Rbac3OutboxFactoryTest {
    @Test
    void retainsOutboxTechnicalReadAndShardGuards() throws Exception {
        var outbox = mock(OutboxManagedDdlInitializer.class);
        when(outbox.isMultiGroupMode()).thenReturn(true);
        var factory = new Rbac3FlywayConfiguration().logicalDataSourceFactory(outbox);

        assertThat(factory).isInstanceOf(OutboxLogicalDataSourceFactory.class);
        assertThat(factory.permitsPrimaryRead((Select) CCJSqlParserUtil.parse(
                "SELECT script,type,version,checksum,route_fingerprint,tenant_id FROM egon_outbox.ddl_history ORDER BY version")))
                .isTrue();
        assertThat(factory.permitsPrimaryRead((Select) CCJSqlParserUtil.parse(
                "SELECT id FROM orders WHERE id = ? FOR UPDATE"))).isFalse();
        assertThat(factory.enforceSingleWriteGroup()).isTrue();
        assertThatThrownBy(() -> factory.validateLogicalSql("SELECT * FROM egon_cola_outbox_message"))
                .isInstanceOf(java.sql.SQLException.class).hasMessageContaining("OUTBOX_SHARD_SQL_INVALID");
    }
}
