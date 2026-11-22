package top.egon.cola.platform.tianquan.jianshen.admin.config.runtime;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.persistence.EntityManager;
import jakarta.persistence.EntityManagerFactory;
import java.time.Clock;
import java.util.List;
import java.util.Map;
import javax.sql.DataSource;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;
import org.springframework.core.io.ClassPathResource;
import org.springframework.transaction.annotation.EnableTransactionManagement;
import top.egon.cola.component.common.core.validation.ValidationUtils;
import top.egon.cola.component.common.mybatis.ddl.EgonColaPostgreDdlRunner;
import top.egon.cola.component.common.mybatis.routing.EgonColaRoutingProfileBO;
import top.egon.cola.component.common.mybatis.routing.EgonColaTwoLevelRouteStrategy;
import top.egon.cola.component.common.mybatis.routing.EgonColaWriteTargetResolver;
import top.egon.cola.component.common.mybatis.sharding.EgonColaShardingProperties;
import top.egon.cola.component.common.mybatis.sharding.bootstrap.EgonColaShardingTopologyValidator;
import top.egon.cola.component.common.mybatis.sharding.resolver.EgonColaShardingWriteTargetResolver;
import top.egon.cola.component.outbox.autoconfigure.OutboxMpStorageProperties;
import top.egon.cola.component.outbox.migration.OutboxManagedDdlInitializer;
import top.egon.cola.platform.tianquan.jianshen.admin.bootstrap.controller.cli.PermissionBootstrapCli;
import top.egon.cola.platform.tianquan.jianshen.admin.bootstrap.domain.dto.PermissionBootstrapConnectionDTO;
import top.egon.cola.platform.tianquan.jianshen.admin.bootstrap.repository.PermissionBootstrapRepository;
import top.egon.cola.platform.tianquan.jianshen.admin.bootstrap.service.PermissionBootstrapService;
import top.egon.cola.platform.tianquan.jianshen.admin.registration.catalog.domain.convertor.PermissionCatalogJson;
import top.egon.cola.platform.tianquan.jianshen.admin.registration.catalog.repository.PermissionCatalogScopeRepository;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.grant.rolepermission.repository.RolePermissionGrantRepository;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.runtime.repository.AuthorizationEventPublisher;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.runtime.repository.outbox.TransactionalOutboxAuthorizationEventPublisher;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.runtime.state.repository.TenantAuthorizationStateRepository;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.runtime.state.repository.jpa.JpaTenantAuthorizationStateRepository;
import top.egon.cola.platform.tianquan.jianshen.admin.shared.domain.DatabaseClock;
import top.egon.cola.platform.tianquan.jianshen.admin.shared.repository.jpa.JpaDatabaseClock;
import top.egon.cola.platform.tianquan.jianshen.admin.audit.service.AuditQueryService;
import top.egon.cola.platform.tianquan.jianshen.admin.audit.repository.AuditRepository;
import top.egon.cola.platform.tianquan.jianshen.admin.audit.repository.jdbc.PostgresqlAuditRepository;
import top.egon.cola.platform.tianquan.jianshen.admin.audit.repository.internal.AuditCursorCodec;

/** Explicit operator context with one database and transaction manager; no application scan or event consumers. */
@EnableTransactionManagement(proxyTargetClass = true)
@org.springframework.boot.context.properties.EnableConfigurationProperties(top.egon.cola.component.outbox.autoconfigure.TransactionalOutboxProperties.class)
@org.springframework.boot.autoconfigure.ImportAutoConfiguration({
        org.springframework.boot.validation.autoconfigure.ValidationAutoConfiguration.class,
        top.egon.cola.component.common.id.autoconfigure.IdGeneratorAutoConfiguration.class,
        top.egon.cola.component.common.mybatis.autoconfigure.EgonColaMybatisPlusAutoConfiguration.class,
        com.baomidou.mybatisplus.autoconfigure.MybatisPlusAutoConfiguration.class,
        top.egon.cola.component.outbox.autoconfigure.OutboxMybatisPlusAutoConfiguration.class,
        top.egon.cola.component.outbox.autoconfigure.OutboxStateMachineAutoConfiguration.class})
public class PermissionBootstrapConfiguration {
    @Bean({"idpClock", "egonColaMybatisPlusClock"}) @Primary
    Clock clock() { return Clock.systemUTC(); }

    @Bean({"jacksonObjectMapper", "outboxStateMachineObjectMapper"})
    ObjectMapper mapper() {
        // Storage manifests permit optional constructor properties; operator input keeps the strict CLI parser.
        return PermissionBootstrapCli.mapper().disable(
                com.fasterxml.jackson.databind.DeserializationFeature.FAIL_ON_MISSING_CREATOR_PROPERTIES);
    }

    @Bean("egonColaShardingTopologyValidator")
    EgonColaShardingTopologyValidator topologyValidator(@Qualifier("egonColaValidationUtils") ValidationUtils validation) {
        return new EgonColaShardingTopologyValidator(validation);
    }

    @Bean("egon.cola.component.mybatis-plus.sharding-top.egon.cola.component.common.mybatis.sharding.EgonColaShardingProperties")
    EgonColaShardingProperties sharding(PermissionBootstrapConnectionDTO input) {
        return EgonColaShardingProperties.builder().mode(EgonColaShardingProperties.ModeEnum.SHARDING)
                .configStyle(EgonColaShardingProperties.ConfigStyleEnum.NATIVE).nativeRulesResource("classpath:rbac-sharding-native.yml")
                .dataSources(List.of(new EgonColaShardingProperties.PhysicalDataSourceProperties("rbac_primary", "rbac_primary",
                        EgonColaShardingProperties.DataSourceRoleEnum.PRIMARY, "org.postgresql.Driver", input.jdbcUrl(), input.username(), ""))).build();
    }

    @Bean("permissionBootstrapTopology")
    EgonColaShardingTopologyValidator.TopologyBO topology(EgonColaShardingTopologyValidator validator,
            EgonColaShardingProperties properties) throws java.io.IOException {
        try (var yaml = new ClassPathResource("rbac-sharding-native.yml").getInputStream()) {
            return validator.validate(properties, yaml.readAllBytes());
        }
    }

    @Bean("egonColaShardingRouteFingerprint")
    String fingerprint(EgonColaShardingTopologyValidator.TopologyBO topology) { return topology.fingerprint(); }

    @Bean("egonColaRoutingProfiles")
    Map<String, EgonColaRoutingProfileBO> profiles(EgonColaShardingTopologyValidator.TopologyBO topology) { return topology.profiles(); }

    @Bean("egonColaWriteTargetResolver")
    EgonColaWriteTargetResolver writeTargetResolver(@Qualifier("egonColaRoutingProfiles") Map<String, EgonColaRoutingProfileBO> profiles,
            EgonColaTwoLevelRouteStrategy strategy, @Qualifier("egonColaValidationUtils") ValidationUtils validation,
            EgonColaShardingTopologyValidator.TopologyBO topology) {
        return new EgonColaShardingWriteTargetResolver(profiles, strategy, validation, topology.fingerprint());
    }

    @Bean("outboxManagedDdlInitializer")
    OutboxManagedDdlInitializer outboxDdl(EgonColaPostgreDdlRunner runner, EgonColaShardingTopologyValidator topology,
            @Qualifier("egonColaValidationUtils") ValidationUtils validation, EgonColaShardingProperties properties,
            @Qualifier("outboxStateMachineObjectMapper") ObjectMapper mapper) {
        return new OutboxManagedDdlInitializer(runner, topology, validation, properties,
                OutboxMpStorageProperties.builder().autoInitializeDdl(false).build(), mapper);
    }

    @Bean("dataSource") @Primary
    DataSource dataSource(@Qualifier("permissionBootstrapPhysicalDataSource") DataSource physical,
            EgonColaShardingTopologyValidator.TopologyBO topology, OutboxManagedDdlInitializer initializer) throws Exception {
        return new top.egon.cola.component.outbox.migration.OutboxLogicalDataSourceFactory(initializer)
                .create(Map.of("rbac_primary", physical), topology.yaml());
    }

    @Bean("entityManagerFactory")
    org.springframework.orm.jpa.LocalContainerEntityManagerFactoryBean entityManagerFactory(@Qualifier("dataSource") DataSource source) {
        var factory = new org.springframework.orm.jpa.LocalContainerEntityManagerFactoryBean();
        factory.setDataSource(source);
        factory.setPackagesToScan("top.egon.cola.platform.tianquan.jianshen.admin");
        factory.setJpaVendorAdapter(new org.springframework.orm.jpa.vendor.HibernateJpaVendorAdapter());
        factory.setJpaPropertyMap(Map.of("hibernate.dialect", "org.hibernate.dialect.PostgreSQLDialect", "hibernate.hbm2ddl.auto", "none",
                "hibernate.boot.allow_jdbc_metadata_access", "false", "hibernate.default_schema", "public", "hibernate.jdbc.time_zone", "UTC"));
        return factory;
    }

    @Bean("jpaSharedEM_entityManagerFactory")
    EntityManager entityManager(@Qualifier("entityManagerFactory") EntityManagerFactory factory) {
        return org.springframework.orm.jpa.SharedEntityManagerCreator.createSharedEntityManager(factory);
    }

    @Bean("transactionManager") @Primary
    org.springframework.orm.jpa.JpaTransactionManager transactions(@Qualifier("entityManagerFactory") EntityManagerFactory factory,
            @Qualifier("dataSource") DataSource source) {
        var transactions = new org.springframework.orm.jpa.JpaTransactionManager(factory);
        transactions.setDataSource(source);
        return transactions;
    }

    @Bean
    PermissionCatalogJson permissionCatalogJson(@Qualifier("jacksonObjectMapper") ObjectMapper mapper) { return new PermissionCatalogJson(mapper); }

    @Bean
    DatabaseClock databaseClock(@Qualifier("jpaSharedEM_entityManagerFactory") EntityManager manager) { return new JpaDatabaseClock(manager); }

    @Bean
    PermissionBootstrapRepository permissionBootstrapRepository(@Qualifier("jpaSharedEM_entityManagerFactory") EntityManager manager, PermissionCatalogJson json) {
        return new PermissionBootstrapRepository(manager, json);
    }

    @Bean
    PermissionCatalogScopeRepository permissionCatalogScopes(@Qualifier("jpaSharedEM_entityManagerFactory") EntityManager manager, PermissionCatalogJson json) {
        return new PermissionCatalogScopeRepository(manager, json);
    }

    @Bean
    RolePermissionGrantRepository rolePermissionGrants(@Qualifier("jpaSharedEM_entityManagerFactory") EntityManager manager) { return new RolePermissionGrantRepository(manager); }

    @Bean
    TenantAuthorizationStateRepository tenantState(@Qualifier("jpaSharedEM_entityManagerFactory") EntityManager manager, DatabaseClock clock) {
        return new JpaTenantAuthorizationStateRepository(manager, clock);
    }

    @Bean
    AuditRepository bootstrapAuditRepository(@Qualifier("jpaSharedEM_entityManagerFactory") EntityManager manager) {
        // The command only appends; it never exports a cursor or installs a host signing key.
        byte[] key = new java.security.SecureRandom().generateSeed(32);
        try { return new PostgresqlAuditRepository(manager, new AuditCursorCodec(key)); }
        finally { java.util.Arrays.fill(key, (byte) 0); }
    }

    @Bean
    AuditQueryService bootstrapAudit(AuditRepository repository, @Qualifier("idpClock") Clock clock) { return new AuditQueryService(repository, clock); }

    @Bean
    AuthorizationEventPublisher bootstrapEvents(top.egon.cola.component.outbox.api.TransactionalOutbox outbox, @Qualifier("idpClock") Clock clock) {
        return new TransactionalOutboxAuthorizationEventPublisher(outbox, clock);
    }

    @Bean
    PermissionBootstrapService permissionBootstrap(PermissionBootstrapRepository repository, PermissionCatalogScopeRepository scopes,
            RolePermissionGrantRepository grants, TenantAuthorizationStateRepository policy, AuthorizationEventPublisher events,
            AuditQueryService audit, DatabaseClock clock, PermissionCatalogJson json, PermissionBootstrapConnectionDTO connection) {
        return new PermissionBootstrapService(repository, scopes, grants, policy, events, audit, clock, json, connection.bindingDigest());
    }

    private record ProducerDestination(String channel, java.util.Set<String> destinations)
            implements top.egon.cola.component.outbox.delivery.DeliveryHandler {
        @Override public void validateDestination(String destination) {
            if (!destinations.contains(destination)) { throw new IllegalArgumentException("PERMISSION_BOOTSTRAP_DESTINATION_INVALID"); }
        }
        @Override public top.egon.cola.component.outbox.delivery.DeliveryResult deliver(
                top.egon.cola.component.outbox.delivery.DeliveryContext context) {
            throw new IllegalStateException("PERMISSION_BOOTSTRAP_DELIVERY_NOT_ENABLED");
        }
    }
    @Bean("outboxInfrastructure")
    top.egon.cola.component.outbox.autoconfigure.OutboxInfrastructure outboxInfrastructure(
            org.springframework.beans.factory.config.ConfigurableListableBeanFactory beans,
            top.egon.cola.component.outbox.autoconfigure.TransactionalOutboxProperties properties,
            @Qualifier("egonColaValidationUtils") ValidationUtils validation) {
        new top.egon.cola.component.outbox.autoconfigure.OutboxConfigurationValidator(validation).validate(properties);
        return new top.egon.cola.component.outbox.autoconfigure.OutboxInfrastructureResolver().resolve(beans, properties);
    }

    @Bean("outboxMessageValidator")
    top.egon.cola.component.outbox.validation.OutboxMessageValidator outboxMessageValidator(
            @Qualifier("jacksonObjectMapper") ObjectMapper mapper,
            top.egon.cola.component.outbox.autoconfigure.TransactionalOutboxProperties properties,
            @Qualifier("egonColaValidationUtils") ValidationUtils validation) {
        return new top.egon.cola.component.outbox.validation.OutboxMessageValidator(mapper,
                Math.toIntExact(properties.getPayload().getMaxBytes().toBytes()), properties.getPayload().getMaxHeaderCount(),
                Math.toIntExact(properties.getPayload().getMaxHeaderBytes().toBytes()), validation);
    }

    @Bean("outboxMetrics")
    top.egon.cola.component.outbox.observability.OutboxMetrics outboxMetrics() {
        return new top.egon.cola.component.outbox.observability.NoopOutboxMetrics();
    }

    @Bean("deliveryHandlerRegistry")
    top.egon.cola.component.outbox.delivery.DeliveryHandlerRegistry deliveryHandlerRegistry() {
        return new top.egon.cola.component.outbox.delivery.DeliveryHandlerRegistry(List.of(
                new ProducerDestination(top.egon.cola.platform.tianquan.jianshen.admin.authorization.runtime.domain.Rbac3RuntimeEventCatalog.CHANNEL,
                        java.util.Set.of("tianquan-jianshen.role.policy-changed.v1"))));
    }

    @Bean("transactionalOutbox")
    top.egon.cola.component.outbox.api.TransactionalOutbox transactionalOutbox(
            @Qualifier("outboxMessageValidator") top.egon.cola.component.outbox.validation.OutboxMessageValidator validator,
            @Qualifier("outboxInfrastructure") top.egon.cola.component.outbox.autoconfigure.OutboxInfrastructure infrastructure,
            @Qualifier("outboxStore") top.egon.cola.component.outbox.store.OutboxStore store,
            @Qualifier("deliveryHandlerRegistry") top.egon.cola.component.outbox.delivery.DeliveryHandlerRegistry handlers,
            @Qualifier("outboxMetrics") top.egon.cola.component.outbox.observability.OutboxMetrics metrics,
            @Qualifier("jacksonObjectMapper") ObjectMapper mapper,
            org.springframework.context.ApplicationEventPublisher events,
            top.egon.cola.component.outbox.autoconfigure.TransactionalOutboxProperties properties) {
        return new top.egon.cola.component.outbox.transaction.DefaultTransactionalOutbox(validator,
                new top.egon.cola.component.outbox.serialization.JacksonOutboxMessageSerializer(mapper),
                new top.egon.cola.component.outbox.api.UuidOutboxIdGenerator(), mapper,
                new top.egon.cola.component.outbox.transaction.OutboxTransactionGuard(infrastructure.dataSource()),
                store, handlers, new top.egon.cola.component.outbox.transaction.OutboxAfterCommitBuffer(events, metrics),
                metrics, properties);
    }

    @Bean(name = "outboxSchemaValidator", initMethod = "validate")
    top.egon.cola.component.outbox.store.OutboxSchemaValidator outboxSchemaValidator(
            @Qualifier("outboxStore") top.egon.cola.component.outbox.store.OutboxStore store,
            @Qualifier("egonColaValidationUtils") ValidationUtils validation) {
        return new top.egon.cola.component.outbox.store.OutboxSchemaValidator(store, validation);
    }


}
