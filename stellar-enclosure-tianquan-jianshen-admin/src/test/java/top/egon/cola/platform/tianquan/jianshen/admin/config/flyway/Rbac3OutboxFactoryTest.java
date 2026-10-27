package top.egon.cola.platform.tianquan.jianshen.admin.config.flyway;

import net.sf.jsqlparser.parser.CCJSqlParserUtil;
import net.sf.jsqlparser.statement.select.Select;
import org.junit.jupiter.api.Test;
import top.egon.cola.component.outbox.migration.OutboxLogicalDataSourceFactory;
import top.egon.cola.component.outbox.migration.OutboxManagedDdlInitializer;
import top.egon.cola.component.common.mybatis.sharding.EgonColaShardingProperties;
import top.egon.cola.component.common.mybatis.sharding.EgonColaShardingProperties.DataSourceRoleEnum;
import top.egon.cola.component.common.mybatis.sharding.EgonColaShardingProperties.PhysicalDataSourceProperties;

import java.util.List;
import java.util.Map;
import javax.sql.DataSource;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

class Rbac3OutboxFactoryTest {
    @Test
    void retainsOutboxTechnicalReadAndShardGuards() throws Exception {
        var outbox = mock(OutboxManagedDdlInitializer.class);
        when(outbox.isMultiGroupMode()).thenReturn(true);
        var factory = new Rbac3FlywayConfiguration().logicalDataSourceFactory(outbox, topology());

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

    @Test
    void flywayUsesOnlyThePrimaryWhenReplicasAreConfigured() {
        var primary = mock(DataSource.class);
        var replica = mock(DataSource.class);
        var sources = Map.of("rbac_primary", primary, "rbac_replica", replica);
        assertThat(Rbac3FlywayConfiguration.rbacPrimary(sources, topology())).isSameAs(primary);
        assertThatThrownBy(() -> Rbac3FlywayConfiguration.rbacPrimary(Map.of("rbac_primary", replica), topology()))
                .isInstanceOf(IllegalStateException.class).hasMessageContaining("RBAC_SINGLE_PRIMARY_REQUIRED");
        verifyNoInteractions(primary, replica);
    }

    @Test
    void flywayRejectsMultiplePrimaryGroupsUntilRbacIsMigratedPerGroup() {
        var sharding = topology();
        sharding.setDataSources(List.of(source("rbac_primary", DataSourceRoleEnum.PRIMARY),
                source("rbac_replica", DataSourceRoleEnum.REPLICA),
                new PhysicalDataSourceProperties("other_primary", "other_group", DataSourceRoleEnum.PRIMARY,
                        "org.postgresql.Driver", "jdbc:postgresql://localhost/other", "test", ""),
                new PhysicalDataSourceProperties("other_replica", "other_group", DataSourceRoleEnum.REPLICA,
                        "org.postgresql.Driver", "jdbc:postgresql://localhost/other", "test", "")));
        assertThatThrownBy(() -> Rbac3FlywayConfiguration.rbacPrimary(Map.of(), sharding))
                .isInstanceOf(IllegalStateException.class).hasMessageContaining("OUTBOX_SINGLE_PRIMARY_REQUIRED");
    }

    private static EgonColaShardingProperties topology() {
        return EgonColaShardingProperties.builder().mode(EgonColaShardingProperties.ModeEnum.SHARDING_READWRITE)
                .configStyle(EgonColaShardingProperties.ConfigStyleEnum.NATIVE).dataSources(List.of(
                        source("rbac_primary", DataSourceRoleEnum.PRIMARY),
                        source("rbac_replica", DataSourceRoleEnum.REPLICA))).build();
    }

    private static PhysicalDataSourceProperties source(String name, DataSourceRoleEnum role) {
        return new PhysicalDataSourceProperties(name, "rbac_primary", role, "org.postgresql.Driver",
                "jdbc:postgresql://localhost/test", "test", "");
    }
}
