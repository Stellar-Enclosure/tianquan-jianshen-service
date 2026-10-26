package top.egon.cola.platform.tianquan.jianshen.admin.bootstrap.controller.cli;

import com.fasterxml.jackson.core.StreamReadFeature;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.MapperFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.json.JsonMapper;
import top.egon.cola.platform.tianquan.jianshen.admin.bootstrap.domain.PermissionBootstrapFiles;
import top.egon.cola.platform.tianquan.jianshen.admin.bootstrap.domain.dto.PermissionAdministratorBootstrapCommandDTO;
import top.egon.cola.platform.tianquan.jianshen.admin.bootstrap.domain.dto.PermissionBootstrapConnectionDTO;
import top.egon.cola.platform.tianquan.jianshen.admin.bootstrap.domain.dto.PermissionBootstrapInvocationDTO;
import top.egon.cola.platform.tianquan.jianshen.admin.bootstrap.domain.dto.PermissionCatalogBootstrapCommandDTO;
import top.egon.cola.platform.tianquan.jianshen.admin.bootstrap.service.PermissionBootstrapService;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.CanonicalJson;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.util.Map;
import java.util.Set;

/** Parses private operator files before the dedicated database context is opened. */
public final class PermissionBootstrapCli {
    public static final String CATALOG = "bootstrap-permission-catalog";
    public static final String ADMIN = "bootstrap-permission-admin";
    private static final int LIMIT = 1024 * 1024;

    private PermissionBootstrapCli() { }

    public static boolean matches(String[] arguments) {
        return arguments != null && arguments.length > 0 && Set.of(CATALOG, ADMIN).contains(arguments[0]);
    }

    public static PermissionBootstrapInvocationDTO read(String[] arguments) throws IOException {
        if (arguments.length != 5 || !matches(arguments) || !"--command-file".equals(arguments[1]) || !"--receipt-file".equals(arguments[3])) {
            throw PermissionBootstrapFiles.rejected();
        }
        var mapper = mapper();
        var commandFile = PermissionBootstrapFiles.path(arguments[2]);
        var receiptFile = PermissionBootstrapFiles.path(arguments[4]);
        PermissionBootstrapFiles.directory(receiptFile.getParent());
        if (Files.exists(receiptFile, LinkOption.NOFOLLOW_LINKS)) PermissionBootstrapFiles.file(receiptFile);
        byte[] bytes = PermissionBootstrapFiles.read(commandFile, LIMIT);
        PermissionCatalogBootstrapCommandDTO catalog = null;
        PermissionAdministratorBootstrapCommandDTO administrator = null;
        String connectionPath;
        if (CATALOG.equals(arguments[0])) {
            catalog = mapper.readValue(bytes, PermissionCatalogBootstrapCommandDTO.class);
            connectionPath = catalog.connectionFile();
        } else {
            administrator = mapper.readValue(bytes, PermissionAdministratorBootstrapCommandDTO.class);
            connectionPath = administrator.connectionFile();
        }
        var connection = mapper.readValue(PermissionBootstrapFiles.read(PermissionBootstrapFiles.path(connectionPath), 16384), PermissionBootstrapConnectionDTO.class);
        PermissionBootstrapFiles.file(PermissionBootstrapFiles.path(connection.passwordFile()));
        var invocation = new PermissionBootstrapInvocationDTO(catalog, administrator, connection, receiptFile, Files.exists(receiptFile, LinkOption.NOFOLLOW_LINKS));
        if (Files.exists(receiptFile, LinkOption.NOFOLLOW_LINKS)) {
            var existing = mapper.readTree(PermissionBootstrapFiles.read(receiptFile, LIMIT));
            if (!invocation.operationId().equals(existing.path("operationId").asText())
                    || !digest(invocation).equals(existing.path("commandDigest").asText())) throw PermissionBootstrapFiles.rejected();
        }
        return invocation;
    }

    public static void run(PermissionBootstrapInvocationDTO invocation, PermissionBootstrapService service) throws IOException {
        var receipt = invocation.catalog() == null ? service.administrator(invocation.administrator(), invocation.existingReceipt()) : service.catalog(invocation.catalog(), invocation.existingReceipt());
        if (!digest(invocation).equals(receipt.commandDigest())) throw new IllegalStateException("BOOTSTRAP_DATABASE_BINDING_MISMATCH");
        PermissionBootstrapFiles.receipt(invocation.receiptFile(), CanonicalJson.write(mapper().convertValue(receipt, Map.class))
                .getBytes(java.nio.charset.StandardCharsets.UTF_8));
    }

    public static String digest(PermissionBootstrapInvocationDTO invocation) {
        return CanonicalJson.digest(Map.of("command", mapper().convertValue(invocation.command(), Map.class),
                "databaseBindingDigest", invocation.connection().bindingDigest()));
    }

    public static ObjectMapper mapper() {
        return JsonMapper.builder().addModule(new com.fasterxml.jackson.datatype.jsr310.JavaTimeModule())
                .enable(StreamReadFeature.STRICT_DUPLICATE_DETECTION).enable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES)
                .enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS).enable(DeserializationFeature.FAIL_ON_NULL_FOR_PRIMITIVES)
                .enable(DeserializationFeature.FAIL_ON_MISSING_CREATOR_PROPERTIES)
                .disable(MapperFeature.ALLOW_COERCION_OF_SCALARS).disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS).build();
    }
}
