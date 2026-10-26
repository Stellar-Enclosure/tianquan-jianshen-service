package top.egon.cola.platform.tianquan.jianshen.manifestcli;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.DefinitionLifecycle;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.PermissionManifest;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.PermissionManifestCanonicalizer;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.PermissionMode;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.PermissionRequirement;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.ResourceAccess;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.ResourceType;

import javax.tools.ToolProvider;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.jar.JarEntry;
import java.util.jar.JarOutputStream;

import static org.junit.jupiter.api.Assertions.*;

class PermissionManifestBuildCliTest {
    @TempDir Path directory;

    @Test
    void packagesCompleteModuleSetWithoutLoadingStaticInitializersAndEmbedsDeterministically() throws Exception {
        Path api = module("api", "a".repeat(40));
        Path model = jar(module("model", "a".repeat(40)), "model.jar");
        Path output = api.resolve(PermissionManifestBuildCli.MANIFEST);
        var cli = new PermissionManifestBuildCli();
        var first = cli.build(List.of(api, model), output, false);
        String evidence = Files.readString(api.resolve(PermissionManifestBuildCli.EVIDENCE));
        assertEquals(PermissionManifest.SnapshotMode.FULL, first.producer().snapshotMode());
        assertEquals(List.of("api", "model"), first.producer().scannedModules());
        assertEquals(1, first.resources().size());
        assertEquals(new PermissionManifestCanonicalizer().canonicalize(first), Files.readString(output));
        assertEquals(first, cli.build(List.of(model, api), output, false));
        assertEquals(evidence, Files.readString(api.resolve(PermissionManifestBuildCli.EVIDENCE)));
        assertTrue(evidence.contains("COMPILED_DIRECTORY"));
        assertTrue(evidence.contains("PACKAGED_JAR"));
    }

    @Test
    void missingFailedAndDuplicateModuleInputsCannotReplaceAnExistingManifest() throws Exception {
        Path api = module("api", "a".repeat(40));
        Path output = directory.resolve("manifest-v1.json");
        Files.writeString(output, "previous-output");
        var cli = new PermissionManifestBuildCli();
        assertThrows(IllegalArgumentException.class, () -> cli.build(List.of(api), output, false));
        assertThrows(IllegalArgumentException.class, () -> cli.build(List.of(api, api), output, false));
        assertEquals("previous-output", Files.readString(output));
        Files.delete(api.resolve("demo/Trap.class"));
        assertThrows(IllegalArgumentException.class, () -> cli.build(List.of(api), output, false));
        assertEquals("previous-output", Files.readString(output));
    }

    @Test
    void differentBuildProvenanceCannotFormAFullManifest() throws Exception {
        Path api = module("api", "a".repeat(40));
        Path model = module("model", "b".repeat(40));
        Path output = directory.resolve("manifest-v1.json");
        assertThrows(IllegalArgumentException.class, () -> new PermissionManifestBuildCli().build(List.of(api, model), output, false));
        assertFalse(Files.exists(output));
    }

    @Test
    void duplicateJsonKeysAndSymlinkedInputsAreRejectedWithoutExecutingCode() throws Exception {
        Path api = module("api", "a".repeat(40));
        Path fragment = api.resolve(PermissionManifestBuildCli.FRAGMENT);
        Files.writeString(fragment, Files.readString(fragment).replace("\"schemaVersion\":\"1.0\"", "\"schemaVersion\":\"1.0\",\"schemaVersion\":\"1.0\""));
        assertThrows(java.io.IOException.class, () -> new PermissionManifestBuildCli().build(List.of(api), directory.resolve("manifest-v1.json"), false));
        Path link = directory.resolve("linked-input");
        Files.createSymbolicLink(link, api);
        assertThrows(IllegalArgumentException.class, () -> new PermissionManifestBuildCli().build(List.of(link), directory.resolve("manifest-v1.json"), false));
    }

    @Test
    void commandFailureDoesNotEchoManifestSourceText() throws Exception {
        Path api = module("api", "a".repeat(40));
        Files.writeString(api.resolve(PermissionManifestBuildCli.FRAGMENT), "source-text-must-not-be-logged");
        var failure = assertThrows(IllegalArgumentException.class, () -> PermissionManifestBuildCli.main(new String[]{"--output",
                directory.resolve("manifest-v1.json").toString(), "--module", api.toString()}));
        assertFalse(failure.toString().contains("source-text-must-not-be-logged"));
        assertNull(failure.getCause());
    }

    @Test
    void finalEvidenceBindsPackagedBytesAndFullManifestWithoutLoadingApplication() throws Exception {
        Path api = module("api", "a".repeat(40));
        Path model = module("model", "a".repeat(40));
        var cli = new PermissionManifestBuildCli();
        var manifest = cli.build(List.of(api, model), api.resolve(PermissionManifestBuildCli.MANIFEST), false);
        Path artifact = jar(api, "application.jar");
        Path evidencePath = directory.resolve("delivery/artifact-evidence.json");
        var evidence = cli.verifyArtifact(artifact, evidencePath);
        assertEquals(java.util.HexFormat.of().formatHex(java.security.MessageDigest.getInstance("SHA-256").digest(Files.readAllBytes(artifact))), evidence.get("artifactDigest"));
        assertEquals(new PermissionManifestCanonicalizer().digests(manifest).manifestDigest(), evidence.get("manifestDigest"));
        assertEquals(Files.readString(api.resolve(PermissionManifestBuildCli.MANIFEST)), Files.readString(evidencePath.resolveSibling("manifest-v1.json")));
        assertTrue(Files.readString(evidencePath).contains("Packaged bytes verified"));
        assertFalse(Files.readString(evidencePath).contains(directory.toString()));
    }

    @Test
    void partialOrTamperedEmbeddedEvidenceInvalidatesPreviousDeliveryEvidence() throws Exception {
        Path api = module("api", "a".repeat(40));
        Path model = module("model", "a".repeat(40));
        var cli = new PermissionManifestBuildCli();
        Path output = directory.resolve("artifact-evidence.json");
        Files.writeString(output, "previous-success");
        assertThrows(IllegalArgumentException.class, () -> cli.verifyArtifact(jar(api, "partial.jar"), output));
        assertFalse(Files.exists(output));
        cli.build(List.of(api, model), api.resolve(PermissionManifestBuildCli.MANIFEST), false);
        Path embedded = api.resolve(PermissionManifestBuildCli.EVIDENCE);
        Files.writeString(embedded, Files.readString(embedded).replace("demo-java", "another-java"));
        Files.writeString(output, "previous-success");
        assertThrows(IllegalArgumentException.class, () -> cli.verifyArtifact(jar(api, "tampered.jar"), output));
        assertFalse(Files.exists(output));
    }

    @Test
    void ambiguousEmbeddedManifestsAreRejected() throws Exception {
        Path api = module("api", "a".repeat(40));
        Path model = module("model", "a".repeat(40));
        var cli = new PermissionManifestBuildCli();
        cli.build(List.of(api, model), api.resolve(PermissionManifestBuildCli.MANIFEST), false);
        Path duplicate = api.resolve("BOOT-INF/classes/" + PermissionManifestBuildCli.MANIFEST);
        Files.createDirectories(duplicate.getParent());
        Files.copy(api.resolve(PermissionManifestBuildCli.MANIFEST), duplicate);
        assertThrows(IllegalArgumentException.class, () -> cli.verifyArtifact(jar(api, "ambiguous.jar"), directory.resolve("artifact-evidence.json")));
    }

    private Path module(String module, String commit) throws Exception {
        Path classes = directory.resolve(module + "-classes");
        Files.createDirectories(classes);
        Path source = directory.resolve(module + "-sources/demo/Trap.java");
        Files.createDirectories(source.getParent());
        Files.writeString(source, "package demo; public class Trap { static { if (System.nanoTime()!=0) throw new AssertionError(\"MUST_NOT_RUN\"); } }");
        assertEquals(0, ToolProvider.getSystemJavaCompiler().run(null, null, null, "-proc:none", "-d", classes.toString(), source.toString()));
        var i18n = new PermissionManifest.I18nReference("demo", "read");
        boolean api = module.equals("api");
        var fragment = new PermissionManifest("1.0", new PermissionManifest.Application("biz", "demo"),
                new PermissionManifest.Producer("demo-java", PermissionManifest.ProducerKind.JAVA, PermissionManifest.SnapshotMode.PARTIAL,
                        List.of("demo."), List.of("api", "model"), List.of(module), false),
                new PermissionManifest.Artifact("demo", commit, "test-build", "1"),
                api ? List.of(new PermissionManifest.PermissionDefinition("demo.read", "Read demo records", i18n, DefinitionLifecycle.ACTIVE)) : List.of(), List.of(),
                api ? List.of(new PermissionManifest.ResourceDefinition("demo.api.read", ResourceType.API, Map.of("paths", List.of("/records")),
                        ResourceAccess.PROTECTED, new PermissionRequirement(PermissionMode.ALL, List.of("demo.read")), null,
                        List.of(PermissionManifest.PrincipalType.USER), List.of(), i18n, DefinitionLifecycle.ACTIVE)) : List.of(), List.of(),
                api ? List.of(new PermissionManifest.Message("demo", "read", "en", Map.of("en", "Read demo"))) : List.of());
        Files.createDirectories(classes.resolve(PermissionManifestBuildCli.FRAGMENT).getParent());
        Files.writeString(classes.resolve(PermissionManifestBuildCli.FRAGMENT), new PermissionManifestCanonicalizer().canonicalize(fragment));
        return classes;
    }

    private Path jar(Path classes, String name) throws Exception {
        Path archive = directory.resolve(name);
        try (var output = new JarOutputStream(Files.newOutputStream(archive)); var paths = Files.walk(classes)) {
            for (Path file : paths.filter(Files::isRegularFile).sorted().toList()) {
                output.putNextEntry(new JarEntry(classes.relativize(file).toString().replace('\\', '/')));
                Files.copy(file, output);
                output.closeEntry();
            }
        }
        return archive;
    }
}
