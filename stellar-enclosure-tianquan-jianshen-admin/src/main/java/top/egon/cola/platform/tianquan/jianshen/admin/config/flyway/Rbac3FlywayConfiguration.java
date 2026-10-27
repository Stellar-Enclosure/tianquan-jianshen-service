package top.egon.cola.platform.tianquan.jianshen.admin.config.flyway;

import javax.sql.DataSource;
import jakarta.persistence.EntityManagerFactory;
import org.apache.ibatis.session.SqlSessionFactory;
import org.flywaydb.core.Flyway;
import org.flywaydb.core.api.MigrationVersion;
import org.mybatis.spring.transaction.SpringManagedTransactionFactory;
import org.springframework.beans.factory.SmartInitializingSingleton;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.orm.jpa.JpaTransactionManager;
import java.util.Map;
import top.egon.cola.component.common.mybatis.sharding.bootstrap.EgonColaShardingDataSourceBootstrapper.LogicalDataSourceFactory;
import top.egon.cola.component.common.mybatis.sharding.EgonColaShardingProperties;
import top.egon.cola.component.outbox.migration.OutboxLogicalDataSourceFactory;
import top.egon.cola.component.outbox.migration.OutboxManagedDdlInitializer;
import top.egon.cola.component.outbox.migration.OutboxStorageTopology;

/** Initializes RBAC and managed Outbox on the same physical PRIMARY before creating the shared logical datasource. */
@Configuration(proxyBeanMethods = false)
public class Rbac3FlywayConfiguration {
    public static final String TIANQUAN_JIANSHEN_FLYWAY = "rbac3Flyway";
    public static final String OUTBOX_FLYWAY = "outboxFlyway";
    public static final String TIANQUAN_JIANSHEN_INITIALIZER = "rbac3FlywayInitializer";
    public static final String OUTBOX_INITIALIZER = "outboxFlywayInitializer";

    @Bean("egonColaShardingLogicalDataSourceFactory")
    LogicalDataSourceFactory logicalDataSourceFactory(@Qualifier("outboxManagedDdlInitializer") OutboxManagedDdlInitializer outbox,
                                                      EgonColaShardingProperties sharding) {
        return new OutboxLogicalDataSourceFactory(outbox) {
            @Override
            public DataSource create(Map<String, DataSource> physical, byte[] yaml) throws Exception {
                // Flyway must finish before ShardingSphere inspects the business table metadata.
                Flyway.configure().configuration(buildRbac3Flyway(rbacPrimary(physical, sharding)).getConfiguration())
                        .defaultSchema("public").schemas("public").load().migrate();
                return super.create(physical, yaml);
            }
        };
    }

    static DataSource rbacPrimary(Map<String, DataSource> physical, EgonColaShardingProperties sharding) {
        var primary = OutboxStorageTopology.singlePrimary(sharding);
        var configured = sharding.getDataSources().stream().map(source -> source.name())
                .collect(java.util.stream.Collectors.toSet());
        if (!"rbac_primary".equals(primary.name()) || !physical.keySet().equals(configured)
                || physical.get(primary.name()) == null) {
            throw new IllegalStateException("RBAC_SINGLE_PRIMARY_REQUIRED");
        }
        return physical.get(primary.name());
    }

    /** Read-only migration status points at the same physical PRIMARY prepared by the datasource factory. */
    @Bean(TIANQUAN_JIANSHEN_FLYWAY)
    Flyway rbac3Flyway(@Qualifier("outboxManagedDdlInitializer") OutboxManagedDdlInitializer initializer,
            @Qualifier("egonColaShardingRouteFingerprint") String fingerprint) {
        return buildRbac3Flyway(initializer.physicalMetadataDataSource(fingerprint));
    }

    @Bean("transactionManager")
    JpaTransactionManager transactionManager(EntityManagerFactory factory, @Qualifier("dataSource") DataSource dataSource) {
        var transaction = new JpaTransactionManager(factory);
        transaction.setDataSource(dataSource);
        return transaction;
    }

    @Bean
    SmartInitializingSingleton rbacOutboxTransactionBinding(@Qualifier("dataSource") DataSource dataSource,
            @Qualifier("transactionManager") JpaTransactionManager transaction,
            @Qualifier("sqlSessionFactory") SqlSessionFactory mybatis) {
        return () -> requireTransactionBinding(dataSource, transaction, mybatis);
    }

    static void requireTransactionBinding(DataSource source, JpaTransactionManager transaction, SqlSessionFactory mybatis) {
        var environment = mybatis.getConfiguration().getEnvironment();
        if (transaction.getDataSource() != source || environment == null || environment.getDataSource() != source
                || !(environment.getTransactionFactory() instanceof SpringManagedTransactionFactory)) {
            throw new IllegalStateException("RBAC_OUTBOX_LOCAL_TRANSACTION_BINDING_REQUIRED");
        }
    }

    public static Flyway buildRbac3Flyway(DataSource dataSource) {
        return Flyway.configure().dataSource(dataSource).locations("classpath:db/migration")
                .table("flyway_schema_history_rbac3").validateMigrationNaming(true).load();
    }

    /** Historical migration reader retained for offline compatibility tests; no host bean executes this retired schema. */
    public static Flyway buildOutboxFlyway(DataSource dataSource) {
        return Flyway.configure().dataSource(dataSource).locations("classpath:db/transactional-outbox/postgresql")
                .table("flyway_schema_history_outbox").baselineOnMigrate(true)
                .baselineVersion(MigrationVersion.fromVersion("0")).validateMigrationNaming(true).load();
    }
}
