package top.egon.cola.platform.tianquan.jianshen.admin.bootstrap;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import top.egon.cola.platform.tianquan.jianshen.admin.bootstrap.controller.cli.PermissionBootstrapCli;
import top.egon.cola.platform.tianquan.jianshen.admin.bootstrap.domain.PermissionBootstrapFiles;
import top.egon.cola.platform.tianquan.jianshen.admin.bootstrap.domain.dto.PermissionBootstrapConnectionDTO;
import top.egon.cola.platform.tianquan.jianshen.admin.bootstrap.domain.dto.PermissionCatalogBootstrapCommandDTO;
import top.egon.cola.platform.tianquan.jianshen.admin.bootstrap.domain.vo.PermissionBootstrapReceiptVO;
import top.egon.cola.platform.tianquan.jianshen.admin.bootstrap.service.PermissionBootstrapService;
import top.egon.cola.platform.tianquan.jianshen.admin.registration.catalog.domain.PermissionCatalogCaller;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.CanonicalJson;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.CatalogScope;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.PermissionManifest;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.time.Instant;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;

class PermissionBootstrapCliTest {
    @TempDir Path directory;
    private Path command;
    private Path connection;
    private Path password;
    private Path receipt;

    @BeforeEach
    void privateFiles() throws Exception {
        Files.setPosixFilePermissions(directory, PosixFilePermissions.fromString("rwx------"));
        command = directory.resolve("command.json"); connection = directory.resolve("connection.json");
        password = directory.resolve("password"); receipt = directory.resolve("receipt.json");
        PermissionBootstrapFiles.create(password, "fixture-password\n".getBytes(StandardCharsets.UTF_8));
        var database = new PermissionBootstrapConnectionDTO("jdbc:postgresql://127.0.0.1/fixture", "fixture", "42", "fixture_owner",
                "fixture_owner", password.toString(), 0, "public");
        PermissionBootstrapFiles.create(connection, PermissionBootstrapCli.mapper().writeValueAsBytes(database));
        var grant = new PermissionCatalogBootstrapCommandDTO.ServiceGrant(URI.create("https://idp.example/tenants/10"), "ci",
                URI.create("https://rbac.example"), List.of(PermissionCatalogCaller.Capability.REGISTER), List.of("refs/heads/main"), false);
        var producer = new PermissionCatalogBootstrapCommandDTO.Producer("r-java", PermissionManifest.ProducerKind.JAVA,
                List.of("r.api."), List.of("system:"), List.of("permission/"), List.of("admin"), List.of(grant));
        var input = new PermissionCatalogBootstrapCommandDTO(1, "00000000-0000-0000-0000-000000000001", connection.toString(),
                new CatalogScope("1", "10", "xingyuan", "rbac", "default", "test"), "20", "RBAC", "30", "40", List.of(producer));
        PermissionBootstrapFiles.create(command, PermissionBootstrapCli.mapper().writeValueAsBytes(input));
    }

    @Test
    void exactCommandHasNoConfigurationFallbackAndRejectsUnknownOrAmbiguousJson() throws Exception {
        assertThat(PermissionBootstrapCli.read(arguments()).catalog().applicationId()).isEqualTo("20");
        assertThatThrownBy(() -> PermissionBootstrapCli.read(new String[]{PermissionBootstrapCli.CATALOG, "--command-file", command.toString()}))
                .hasMessage("PERMISSION_BOOTSTRAP_INPUT_UNSAFE");
        String original = Files.readString(command);
        for (String invalid : List.of(original + " {}", original.replace("\"schemaVersion\":1", "\"schemaVersion\":\"1\""),
                original.substring(0, original.length() - 1) + ",\"schemaVersion\":1}",
                original.substring(0, original.length() - 1) + ",\"permissionCodes\":[\"*\"]}")) {
            Files.writeString(command, invalid);
            assertThatThrownBy(() -> PermissionBootstrapCli.read(arguments())).isInstanceOf(Exception.class);
        }
    }

    @Test
    void commandDatabaseSecretAndReceiptMustUseOwnerOnlyFiles() throws Exception {
        for (Path file : List.of(command, connection, password)) {
            Files.setPosixFilePermissions(file, PosixFilePermissions.fromString("rw-r-----"));
            assertThatThrownBy(() -> PermissionBootstrapCli.read(arguments())).hasMessage("PERMISSION_BOOTSTRAP_INPUT_UNSAFE");
            Files.setPosixFilePermissions(file, PosixFilePermissions.fromString("rw-------"));
        }
        Files.setPosixFilePermissions(directory, PosixFilePermissions.fromString("rwxr-x---"));
        assertThatThrownBy(() -> PermissionBootstrapCli.read(arguments())).hasMessage("PERMISSION_BOOTSTRAP_INPUT_UNSAFE");
    }

    @Test
    void privateChildrenUnderANonStickyWritableAncestorCannotSupplyCommandsOrSecrets() throws Exception {
        Path shared = Files.createDirectory(directory.resolve("shared"));
        Files.setPosixFilePermissions(shared, PosixFilePermissions.fromString("rwxrwxrwx"));
        Path child = Files.createDirectory(shared.resolve("private"));
        Files.setPosixFilePermissions(child, PosixFilePermissions.fromString("rwx------"));
        Path unsafeCommand = Files.copy(command, child.resolve("command.json"));
        Path unsafeSecret = Files.copy(password, child.resolve("password"));
        for (Path file : List.of(unsafeCommand, unsafeSecret)) {
            Files.setPosixFilePermissions(file, PosixFilePermissions.fromString("rw-------"));
            assertThatThrownBy(() -> PermissionBootstrapFiles.read(file, 1048576)).hasMessage("PERMISSION_BOOTSTRAP_INPUT_UNSAFE");
        }
        assertThatThrownBy(() -> PermissionBootstrapCli.read(new String[]{PermissionBootstrapCli.CATALOG, "--command-file", unsafeCommand.toString(),
                "--receipt-file", receipt.toString()})).hasMessage("PERMISSION_BOOTSTRAP_INPUT_UNSAFE");
        assertThatThrownBy(() -> PermissionBootstrapFiles.receipt(child.resolve("receipt.json"), new byte[]{1})).hasMessage("PERMISSION_BOOTSTRAP_INPUT_UNSAFE");
    }

    @Test
    void aTrustedRealDirectoryCannotBeReachedThroughAnUntrustedAncestorAlias() throws Exception {
        Path anchor = Files.createDirectory(directory.resolve("anchor"));
        Path child = Files.createDirectory(anchor.resolve("private"));
        Files.setPosixFilePermissions(anchor, PosixFilePermissions.fromString("rwx------"));
        Files.setPosixFilePermissions(child, PosixFilePermissions.fromString("rwx------"));
        Path secret = child.resolve("password");
        PermissionBootstrapFiles.create(secret, "private-secret".getBytes(StandardCharsets.UTF_8));
        Path shared = Files.createDirectory(directory.resolve("shared"));
        Files.setPosixFilePermissions(shared, PosixFilePermissions.fromString("rwxrwxrwx"));
        Path alias = shared.resolve("alias"); Files.createSymbolicLink(alias, anchor);
        assertThatThrownBy(() -> PermissionBootstrapFiles.read(alias.resolve("private/password"), 1024)).hasMessage("PERMISSION_BOOTSTRAP_INPUT_UNSAFE");
        assertThat(PermissionBootstrapFiles.read(secret, 1024)).isEqualTo("private-secret".getBytes(StandardCharsets.UTF_8));
    }

    @Test
    void symlinksRelativePathsAndOversizedCommandsAreRejectedBeforeAContextExists() throws Exception {
        var link = directory.resolve("command-link.json"); Files.createSymbolicLink(link, command);
        assertThatThrownBy(() -> PermissionBootstrapCli.read(new String[]{PermissionBootstrapCli.CATALOG, "--command-file", link.toString(), "--receipt-file", receipt.toString()}))
                .hasMessage("PERMISSION_BOOTSTRAP_INPUT_UNSAFE");
        assertThatThrownBy(() -> PermissionBootstrapFiles.path("command.json")).hasMessage("PERMISSION_BOOTSTRAP_INPUT_UNSAFE");
        assertThatThrownBy(() -> PermissionBootstrapFiles.path(directory + "/../command.json")).hasMessage("PERMISSION_BOOTSTRAP_INPUT_UNSAFE");
        Files.writeString(command, "x".repeat(1048577));
        assertThatThrownBy(() -> PermissionBootstrapCli.read(arguments())).hasMessage("PERMISSION_BOOTSTRAP_INPUT_UNSAFE");
    }

    @Test
    void committedReceiptIsCanonicalSecretFreeAndImmutableOnRecovery() throws Exception {
        var invocation = PermissionBootstrapCli.read(arguments()); var input = invocation.catalog();
        var result = new PermissionBootstrapReceiptVO(1, "B0", input.operationId(), PermissionBootstrapCli.digest(invocation), input.target(),
                input.applicationId(), input.ddcBusinessId(), input.ddcApplicationId(), List.of("r-java"), Map.of("z", "2", "a", "1"), Instant.parse("2026-10-25T00:00:00Z"));
        var service = mock(PermissionBootstrapService.class);
        when(service.catalog(input, false)).thenReturn(result); when(service.catalog(input, true)).thenReturn(result);
        PermissionBootstrapCli.run(invocation, service);
        String original = Files.readString(receipt);
        assertThat(original).isEqualTo(CanonicalJson.write(PermissionBootstrapCli.mapper().convertValue(result, Map.class)))
                .doesNotContain("fixture-password", "jdbc:", "passwordFile");
        assertThat(Files.getPosixFilePermissions(receipt)).isEqualTo(PosixFilePermissions.fromString("rw-------"));
        var resumed = PermissionBootstrapCli.read(arguments()); assertThat(resumed.existingReceipt()).isTrue();
        PermissionBootstrapCli.run(resumed, service);
        assertThat(Files.readString(receipt)).isEqualTo(original);
        assertThatThrownBy(() -> PermissionBootstrapFiles.receipt(receipt, "different".getBytes(StandardCharsets.UTF_8)))
                .hasMessage("PERMISSION_BOOTSTRAP_INPUT_UNSAFE");
        assertThat(Files.readString(receipt)).isEqualTo(original);
        Files.writeString(command, Files.readString(command).replace("\"applicationName\":\"RBAC\"", "\"applicationName\":\"Changed\""));
        assertThatThrownBy(() -> PermissionBootstrapCli.read(arguments())).hasMessage("PERMISSION_BOOTSTRAP_INPUT_UNSAFE");
    }

    private String[] arguments() { return new String[]{PermissionBootstrapCli.CATALOG, "--command-file", command.toString(), "--receipt-file", receipt.toString()}; }
}
