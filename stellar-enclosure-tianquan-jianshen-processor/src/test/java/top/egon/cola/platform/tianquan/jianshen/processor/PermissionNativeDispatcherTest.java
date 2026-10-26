package top.egon.cola.platform.tianquan.jianshen.processor;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import static org.junit.jupiter.api.Assertions.*;

class PermissionNativeDispatcherTest {
    @TempDir Path directory;
    private static final String SOURCE = """
            final class Example {
                private Example() { }
                @PermissionNativeDispatcher(routeType=Route.class,pathAccessor="pathPattern",methodsAccessor="methods")
                @PermissionResource(key="demo.api.dispatch",type=ResourceType.API,access=ResourceAccess.INTERNAL,
                    labelPage="native",labelKey="dispatch")
                public static void dispatch() { throw new UnsupportedOperationException(); }
            }
            record Route(String pathPattern, java.util.Set<String> methods) {
                static { if (true) throw new AssertionError("producer class must never load"); }
            }
            """;

    @Test void exportsTheActualDynamicRouteSourceWithoutInventingFinitePathsOrMethods() throws Exception {
        var result = CompilerFixture.compile(directory, SOURCE, Map.of("metadataOnlyTypes", "demo.Example"));
        assertTrue(result.success(), result.diagnostics());
        assertEquals(Map.of("nativeRouteType", "demo.Route", "pathSource", "pathPattern", "methodSource", "methods", "protocol", "HTTP"),
                result.manifest().resources().getFirst().target());
        assertTrue(result.manifest().resources().getFirst().target().keySet().stream().noneMatch(key -> key.equals("paths") || key.equals("methods")));
    }

    @Test void rejectsOrdinaryControllersPublicProtectedAndSpringMappedDeclarations() throws Exception {
        var unlisted = CompilerFixture.compile(directory.resolve("unlisted"), SOURCE);
        assertFalse(unlisted.success()); assertTrue(unlisted.diagnostics().contains("exact metadata-only holder"), unlisted.diagnostics());
        List<String> invalid = List.of(SOURCE.replace("ResourceAccess.INTERNAL", "ResourceAccess.PUBLIC"),
                SOURCE.replace("ResourceAccess.INTERNAL", "ResourceAccess.PROTECTED"),
                SOURCE.replace("@PermissionNativeDispatcher", "@GetMapping(\"/**\") @PermissionNativeDispatcher"),
                SOURCE.replace("final class Example", "@RestController final class Example"),
                SOURCE.replace("public static void dispatch", "public void dispatch"));
        for (int i=0; i<invalid.size(); i++) {
            var result = CompilerFixture.compile(directory.resolve("invalid"+i), invalid.get(i), Map.of("metadataOnlyTypes", "demo.Example"));
            assertFalse(result.success(), "invalid dispatcher " + i); assertFalse(java.nio.file.Files.exists(result.fragmentPath()));
        }
    }

    @Test void rejectsMissingParameterizedStaticRawWildcardAndWrongTypedAccessors() throws Exception {
        List<String> invalid = List.of(SOURCE.replace("pathAccessor=\"pathPattern\"", "pathAccessor=\"missing\""),
                SOURCE.replace("String pathPattern", "int pathPattern"), SOURCE.replace("Set<String>", "Set<Integer>"),
                SOURCE.replace("Set<String>", "Set<?>"), SOURCE.replace("Set<String>", "Set"),
                SOURCE.replace("pathAccessor=\"pathPattern\"", "pathAccessor=\"pathPattern()\""),
                SOURCE.replace("record Route(String pathPattern, java.util.Set<String> methods)",
                        "class Route").replace("static { if (true)", "public static String pathPattern() { return \"/**\"; } public java.util.Set<String> methods() { return java.util.Set.of(); } static { if (true)"),
                SOURCE.replace("record Route(String pathPattern, java.util.Set<String> methods)",
                        "class Route").replace("static { if (true)", "public String pathPattern(String input) { return input; } public java.util.Set<String> methods() { return java.util.Set.of(); } static { if (true)"));
        for (int i=0; i<invalid.size(); i++) {
            var result = CompilerFixture.compile(directory.resolve("accessor"+i), invalid.get(i), Map.of("metadataOnlyTypes", "demo.Example"));
            assertFalse(result.success(), "invalid accessor " + i); assertFalse(java.nio.file.Files.exists(result.fragmentPath()));
        }
    }
}
