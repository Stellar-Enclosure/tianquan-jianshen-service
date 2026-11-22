package top.egon.cola.platform.tianquan.jianshen.admin.config.runtime;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import top.egon.cola.platform.tianquan.jianshen.admin.bootstrap.domain.PermissionBootstrapFiles;
import top.egon.cola.platform.tianquan.jianshen.admin.bootstrap.domain.dto.PermissionBootstrapConnectionDTO;
import top.egon.cola.platform.tianquan.jianshen.admin.bootstrap.service.PermissionBootstrapService;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

class PermissionBootstrapConfigurationTest {
    @TempDir Path directory;

    @Test
    void ownerContextUsesOneJpaAndOutboxDataSourceWithoutWebDeliveryOrApplicationScanning() throws Exception {
        var input = connection();
        var dataSource = mock(javax.sql.DataSource.class);
        var sql = mock(org.apache.ibatis.session.SqlSessionFactory.class);
        var configuration = new com.baomidou.mybatisplus.core.MybatisConfiguration();
        configuration.setEnvironment(new org.apache.ibatis.mapping.Environment("fixture",
                new org.mybatis.spring.transaction.SpringManagedTransactionFactory(), dataSource));
        when(sql.getConfiguration()).thenReturn(configuration);
        var store = mock(top.egon.cola.component.outbox.store.OutboxStore.class);
        var entityManagers = mock(jakarta.persistence.EntityManagerFactory.class);
        when(entityManagers.isOpen()).thenReturn(true);
        try (var context = PermissionBootstrapCommandRunner.context(input, "00000000-0000-0000-0000-000000000001")) {
            context.addBeanFactoryPostProcessor(factory -> {
                factory.registerSingleton("dataSource", dataSource);
                factory.registerSingleton("entityManagerFactory", entityManagers);
                factory.registerSingleton("sqlSessionFactory", sql);
                factory.registerSingleton("outboxStore", store);
                // This factory is a fixture; production retains the Common interceptor contract validator.
                factory.registerSingleton("egonColaMybatisPlusContractValidator", mock(
                        top.egon.cola.component.common.mybatis.autoconfigure.EgonColaMybatisPlusContractValidator.class));
            });
            context.refresh();
            assertThat(context.getBean(PermissionBootstrapService.class)).isNotNull();
            assertThat(org.springframework.aop.support.AopUtils.isAopProxy(context.getBean(PermissionBootstrapService.class))).isTrue();
            assertThat(context.getBean(org.springframework.orm.jpa.JpaTransactionManager.class).getDataSource()).isSameAs(dataSource);
            assertThat(context.getBean(top.egon.cola.component.outbox.autoconfigure.OutboxInfrastructure.class).dataSource()).isSameAs(dataSource);
            assertThat(context.getBeansOfType(org.springframework.boot.ApplicationRunner.class)).isEmpty();
            assertThat(context.getBeansOfType(org.springframework.boot.CommandLineRunner.class)).isEmpty();
            assertThat(context.getBeansOfType(org.springframework.scheduling.TaskScheduler.class)).isEmpty();
            assertThat(context.getBeansOfType(org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerMapping.class)).isEmpty();
            assertThat(context.getEnvironment().getPropertySources().contains("systemEnvironment")).isFalse();
            assertThat(context.getEnvironment().getPropertySources().contains("systemProperties")).isFalse();
            verify(dataSource, never()).getConnection();
            verify(entityManagers, never()).createEntityManager();
        }
    }

    @Test
    void storageManifestAllowsItsOptionalBaselineWhileOperatorCommandsRemainStrict() throws Exception {
        var storageMapper = new PermissionBootstrapConfiguration().mapper();
        try (var manifest = new org.springframework.core.io.ClassPathResource("db/egon-outbox-mp/manifest.json").getInputStream()) {
            assertThat(storageMapper.readValue(manifest,
                    top.egon.cola.component.common.mybatis.ddl.EgonColaDdlManifestBO.class).family())
                    .isEqualTo("component-outbox");
        }
        assertThat(top.egon.cola.platform.tianquan.jianshen.admin.bootstrap.controller.cli.PermissionBootstrapCli.mapper()
                .isEnabled(com.fasterxml.jackson.databind.DeserializationFeature.FAIL_ON_MISSING_CREATOR_PROPERTIES)).isTrue();
        assertThatThrownBy(() -> storageMapper.readValue("{\"family\":\"component-outbox\"}",
                top.egon.cola.component.common.mybatis.ddl.EgonColaDdlManifestBO.class)).isInstanceOf(Exception.class);
    }

    @Test
    void everyBorrowedConnectionMustMatchDatabaseOidOwnerUserAndNativeSchema() throws Exception {
        var input = connection();
        var source = PermissionBootstrapCommandRunner.guardedDataSource(input);
        var properties = org.apache.shardingsphere.infra.datasource.pool.props.creator.DataSourcePoolPropertiesCreator.create(source)
                .getConnectionPropertySynonyms().getStandardProperties();
        assertThat(properties).containsEntry("url", input.jdbcUrl() + "?connectTimeout=5&socketTimeout=30&currentSchema=public")
                .containsEntry("username", "fixture_owner");
        assertThatThrownBy(() -> source.getConnection("foreign", "unused")).hasMessage("PERMISSION_BOOTSTRAP_INPUT_UNSAFE");
        var connection = mock(Connection.class); var query = mock(PreparedStatement.class); var rows = mock(ResultSet.class);
        when(connection.prepareStatement(anyString())).thenReturn(query); when(query.executeQuery()).thenReturn(rows);
        when(rows.next()).thenReturn(true, false); when(rows.getString(1)).thenReturn("fixture"); when(rows.getString(2)).thenReturn("43");
        when(rows.getString(3)).thenReturn("fixture_owner"); when(rows.getString(4)).thenReturn("fixture_owner"); when(rows.getString(5)).thenReturn("public");
        assertThatThrownBy(() -> PermissionBootstrapCommandRunner.verifyDatabase(connection, input)).hasMessage("PERMISSION_BOOTSTRAP_TARGET_MISMATCH");
        verify(query).close(); verify(rows).close();
        reset(rows); when(rows.next()).thenReturn(true, false); when(rows.getString(1)).thenReturn("fixture"); when(rows.getString(2)).thenReturn("42");
        when(rows.getString(3)).thenReturn("fixture_owner"); when(rows.getString(4)).thenReturn("fixture_owner"); when(rows.getString(5)).thenReturn("public");
        assertThatCode(() -> PermissionBootstrapCommandRunner.verifyDatabase(connection, input)).doesNotThrowAnyException();
    }

    @Test
    void incompleteSchemaIsRejectedWithoutRunningAMigration() throws Exception {
        var connection = mock(Connection.class); var query = mock(PreparedStatement.class); var rows = mock(ResultSet.class);
        when(connection.prepareStatement(anyString())).thenReturn(query); when(query.executeQuery()).thenReturn(rows);
        when(rows.next()).thenReturn(true); when(rows.getInt(1)).thenReturn(0);
        assertThatThrownBy(() -> PermissionBootstrapCommandRunner.verifySchema(connection)).hasMessage("PERMISSION_BOOTSTRAP_SCHEMA_NOT_READY");
        verify(query, never()).executeUpdate();
    }

    private PermissionBootstrapConnectionDTO connection() throws Exception {
        Files.setPosixFilePermissions(directory, PosixFilePermissions.fromString("rwx------"));
        var password = directory.resolve("password");
        if (!Files.exists(password)) PermissionBootstrapFiles.create(password, "fixture-password\n".getBytes(StandardCharsets.UTF_8));
        return new PermissionBootstrapConnectionDTO("jdbc:postgresql://127.0.0.1:5432/fixture", "fixture", "42", "fixture_owner", "fixture_owner", password.toString(), 0, "public");
    }
}
