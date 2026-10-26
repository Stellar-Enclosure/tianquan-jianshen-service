package top.egon.cola.platform.tianquan.jianshen.admin.config.runtime;

import org.springframework.context.annotation.AnnotationConfigApplicationContext;
import org.springframework.core.env.MapPropertySource;
import org.springframework.jdbc.datasource.AbstractDataSource;
import top.egon.cola.platform.tianquan.jianshen.admin.bootstrap.controller.cli.PermissionBootstrapCli;
import top.egon.cola.platform.tianquan.jianshen.admin.bootstrap.domain.PermissionBootstrapFiles;
import top.egon.cola.platform.tianquan.jianshen.admin.bootstrap.domain.dto.PermissionBootstrapConnectionDTO;
import top.egon.cola.platform.tianquan.jianshen.admin.bootstrap.service.PermissionBootstrapService;

import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.SQLException;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Map;

/** Opens only the explicit database-owner context after private input and target identity checks. */
public final class PermissionBootstrapCommandRunner {
    private PermissionBootstrapCommandRunner() { }

    public static int run(String[] arguments) {
        try {
            if ("true".equalsIgnoreCase(System.getenv("CI"))) throw PermissionBootstrapFiles.rejected();
            var invocation = PermissionBootstrapCli.read(arguments);
            try (var connection = guardedDataSource(invocation.connection()).getConnection()) { verifySchema(connection); }
            try (var context = open(invocation.connection(), invocation.operationId())) {
                PermissionBootstrapCli.run(invocation, context.getBean(PermissionBootstrapService.class));
            }
            System.out.println("PERMISSION_BOOTSTRAP_COMMITTED");
            return 0;
        } catch (Exception failure) {
            // Driver errors can include connection details; the database audit is the original outcome authority.
            System.err.println("PERMISSION_BOOTSTRAP_FAILED: inspect the private command and receipt; retry the same operation after correcting the cause");
            return 1;
        }
    }

    static AnnotationConfigApplicationContext open(PermissionBootstrapConnectionDTO input, String operationId) {
        var context = context(input, operationId);
        try { context.refresh(); return context; }
        catch (RuntimeException failure) { context.close(); throw failure; }
    }

    static AnnotationConfigApplicationContext context(PermissionBootstrapConnectionDTO input, String operationId) {
        var context = new AnnotationConfigApplicationContext();
        context.setBeanNameGenerator(new org.springframework.context.annotation.AnnotationBeanNameGenerator());
        context.getBeanFactory().setConversionService(org.springframework.boot.convert.ApplicationConversionService.getSharedInstance());
        context.getEnvironment().getPropertySources().remove(org.springframework.core.env.StandardEnvironment.SYSTEM_ENVIRONMENT_PROPERTY_SOURCE_NAME);
        context.getEnvironment().getPropertySources().remove(org.springframework.core.env.StandardEnvironment.SYSTEM_PROPERTIES_PROPERTY_SOURCE_NAME);
        Map<String, Object> properties = new LinkedHashMap<>();
        properties.put("egon.cola.component.id.machine-id", input.idMachineId());
        properties.put("egon.cola.component.mybatis-plus.tenant-id.ignored-tables[0]", "egon_cola_outbox_message");
        properties.put("egon.cola.component.transactional-outbox.node-id", "permission-bootstrap:" + operationId);
        properties.put("egon.cola.component.transactional-outbox.storage.data-source-bean-name", "dataSource");
        properties.put("egon.cola.component.transactional-outbox.storage.transaction-manager-bean-name", "transactionManager");
        properties.put("egon.cola.component.transactional-outbox.state-machine.business.enabled", "false");
        properties.put("egon.cola.component.transactional-outbox.storage.mp.auto-initialize-ddl", "false");
        properties.put("mybatis-plus.mapper-locations", "classpath*:mapper/**/*.xml");
        context.getEnvironment().getPropertySources().addFirst(new MapPropertySource("permissionBootstrap", properties));
        context.registerBean("permissionBootstrapConnection", PermissionBootstrapConnectionDTO.class, () -> input);
        context.registerBean("permissionBootstrapPhysicalDataSource", javax.sql.DataSource.class, () -> guardedDataSource(input));
        context.register(PermissionBootstrapConfiguration.class);
        return context;
    }

    static javax.sql.DataSource guardedDataSource(PermissionBootstrapConnectionDTO input) { return new GuardedDataSource(input); }

    /** Native routing reads these JavaBean properties; every physical connection is independently verified. */
    public static final class GuardedDataSource extends AbstractDataSource {
        private final PermissionBootstrapConnectionDTO input;

        GuardedDataSource(PermissionBootstrapConnectionDTO input) { this.input = input; }

        public String getUrl() { return input.jdbcUrl() + "?connectTimeout=5&socketTimeout=30&currentSchema=public"; }
        public String getUsername() { return input.username(); }
        @com.fasterxml.jackson.annotation.JsonIgnore
        public String getPassword() {
            byte[] bytes = null;
            try {
                bytes = PermissionBootstrapFiles.read(PermissionBootstrapFiles.path(input.passwordFile()), 4096);
                String password = new String(bytes, StandardCharsets.UTF_8).replaceFirst("\\r?\\n$", "");
                if (password.isEmpty()) throw PermissionBootstrapFiles.rejected();
                return password;
            } catch (java.io.IOException failure) { throw new IllegalStateException("PERMISSION_BOOTSTRAP_CREDENTIAL_UNAVAILABLE", failure); }
            finally { if (bytes != null) Arrays.fill(bytes, (byte) 0); }
        }

        @Override public Connection getConnection() throws SQLException {
            Connection connection = java.sql.DriverManager.getConnection(getUrl(), getUsername(), getPassword());
            try { verifyDatabase(connection, input); return connection; }
            catch (RuntimeException | SQLException failure) {
                try { connection.close(); } catch (SQLException close) { failure.addSuppressed(close); }
                throw new SQLException("PERMISSION_BOOTSTRAP_TARGET_UNAVAILABLE", failure);
            }
        }

        @Override public Connection getConnection(String username, String password) { throw PermissionBootstrapFiles.rejected(); }
    }

    static void verifyDatabase(Connection connection, PermissionBootstrapConnectionDTO input) throws SQLException {
        try (var query = connection.prepareStatement("""
                select current_database(), d.oid::text, pg_get_userbyid(d.datdba), current_user, current_schema()
                  from pg_database d where d.datname=current_database()
                """)) {
            query.setQueryTimeout(5);
            try (var rows = query.executeQuery()) {
                if (!rows.next() || !input.databaseName().equals(rows.getString(1)) || !input.databaseOid().equals(rows.getString(2))
                        || !input.databaseOwner().equals(rows.getString(3)) || !input.username().equals(rows.getString(4))
                        || !input.schema().equals(rows.getString(5)) || rows.next()) throw new IllegalStateException("PERMISSION_BOOTSTRAP_TARGET_MISMATCH");
            }
        }
    }

    static void verifySchema(Connection connection) throws SQLException {
        try (var query = connection.prepareStatement("""
                select count(*) from public.flyway_schema_history_rbac3 where version='16' and success
                """)) {
            query.setQueryTimeout(5);
            try (var rows = query.executeQuery()) {
                if (!rows.next() || rows.getInt(1) != 1) throw new IllegalStateException("PERMISSION_BOOTSTRAP_SCHEMA_NOT_READY");
            }
        }
    }
}
