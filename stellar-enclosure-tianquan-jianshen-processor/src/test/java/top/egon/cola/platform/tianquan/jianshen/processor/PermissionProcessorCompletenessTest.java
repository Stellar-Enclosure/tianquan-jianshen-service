package top.egon.cola.platform.tianquan.jianshen.processor;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.PermissionManifest;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.PermissionManifestCanonicalizer;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PermissionProcessorCompletenessTest {

    @TempDir
    Path directory;

    private static final String SOURCE = """
            @RestController class Example {
              @GetMapping("/a") @PermissionResource(key="demo.a", type=ResourceType.API, labelPage="demo", labelKey="a", access=ResourceAccess.PUBLIC)
              String a() { return "a"; }
            }
            """;

    @Test
    void neverMarksCompilerOutputFullIncludingLateBodyErrors() throws Exception {
        var valid = CompilerFixture.compile(directory.resolve("valid"), SOURCE);
        assertTrue(valid.success(), valid.diagnostics());
        assertEquals(PermissionManifest.SnapshotMode.PARTIAL, valid.manifest().producer().snapshotMode());
        var invalid = CompilerFixture.compile(directory.resolve("invalid"), SOURCE.replace("return \"a\"", "return unknownVariable"));
        assertFalse(invalid.success());
        if (Files.exists(invalid.fragmentPath())) {
            assertEquals(PermissionManifest.SnapshotMode.PARTIAL, invalid.manifest().producer().snapshotMode());
        }
    }

    @Test
    void missingModuleAndDuplicateArtifactCannotBecomeFull() throws Exception {
        var result = CompilerFixture.compile(directory, SOURCE, Map.of("expectedModules", "api,dto"));
        assertTrue(result.success(), result.diagnostics());
        var module = new PermissionManifestAggregator.BuiltModule(result.manifest(), "a".repeat(64));
        var aggregator = new PermissionManifestAggregator();
        assertThrows(IllegalArgumentException.class, () -> aggregator.aggregate(List.of(module), false));
        assertThrows(IllegalArgumentException.class, () -> aggregator.aggregate(List.of(module, module), false));
        assertThrows(IllegalArgumentException.class, () -> new PermissionManifestAggregator.BuiltModule(result.manifest(), null));
    }

    @Test
    void completeArtifactsAggregateDeterministicallyAndResolveInternalReferences() throws Exception {
        var api = CompilerFixture.compile(directory.resolve("api"), """
                @RestController @PermissionReferences("demo.read") class Example {
                  @GetMapping("/a") @PermissionResource(key="demo.a", type=ResourceType.API, labelPage="demo", labelKey="a")
                  @RequiresPermissions(codes="demo.read") String a() { return "a"; }
                }
                """, Map.of("expectedModules", "api,dto"));
        var dto = CompilerFixture.compile(directory.resolve("dto"), """
                @PermissionDefinition(code="demo.read", meaning="Read records", labelPage="demo", labelKey="a")
                class Example {}
                """, Map.of("expectedModules", "api,dto", "module", "dto"));
        assertTrue(api.success(), api.diagnostics());
        assertTrue(dto.success(), dto.diagnostics());
        var a = new PermissionManifestAggregator.BuiltModule(api.manifest(), "a".repeat(64));
        var b = new PermissionManifestAggregator.BuiltModule(dto.manifest(), "b".repeat(64));
        var aggregator = new PermissionManifestAggregator();
        var full = aggregator.aggregate(List.of(a, b), false);
        assertEquals(PermissionManifest.SnapshotMode.FULL, full.producer().snapshotMode());
        assertEquals(List.of("api", "dto"), full.producer().scannedModules());
        assertEquals(List.of(), full.permissionReferences());
        var canonical = new PermissionManifestCanonicalizer();
        assertEquals(canonical.canonicalize(full), canonical.canonicalize(aggregator.aggregate(List.of(b, a), false)));
    }

    @Test
    void rejectsMixedBuildProvenance() throws Exception {
        var api = CompilerFixture.compile(directory.resolve("api"), SOURCE, Map.of("expectedModules", "api,dto"));
        var dto = CompilerFixture.compile(directory.resolve("dto"), "class Example {}",
                Map.of("expectedModules", "api,dto", "module", "dto", "commit", "b".repeat(40)));
        assertTrue(api.success(), api.diagnostics());
        assertTrue(dto.success(), dto.diagnostics());
        var a = new PermissionManifestAggregator.BuiltModule(api.manifest(), "a".repeat(64));
        var b = new PermissionManifestAggregator.BuiltModule(dto.manifest(), "b".repeat(64));
        assertThrows(IllegalArgumentException.class, () -> new PermissionManifestAggregator().aggregate(List.of(a, b), false));
    }

    @Test
    void emptyFullRequiresExplicitClearIntent() throws Exception {
        var empty = CompilerFixture.compile(directory, "class Example {}");
        assertTrue(empty.success(), empty.diagnostics());
        var module = new PermissionManifestAggregator.BuiltModule(empty.manifest(), "a".repeat(64));
        var aggregator = new PermissionManifestAggregator();
        assertThrows(IllegalArgumentException.class, () -> aggregator.aggregate(List.of(module), false));
        assertTrue(aggregator.aggregate(List.of(module), true).producer().clearIntent());
    }

    @Test
    void missingBuildOptionsCannotEmitFragment() throws Exception {
        var result = CompilerFixture.compile(directory, SOURCE, Map.of("buildId", ""));
        assertFalse(result.success());
        assertTrue(result.diagnostics().contains("pac.buildId"));
        assertFalse(Files.exists(result.fragmentPath()));
        var unresolved = CompilerFixture.compile(directory.resolve("unresolved"), SOURCE, Map.of("buildId", "${permission.buildId}"));
        assertFalse(unresolved.success());
        assertTrue(unresolved.diagnostics().contains("pac.buildId"));
        assertFalse(Files.exists(unresolved.fragmentPath()));
    }
}
