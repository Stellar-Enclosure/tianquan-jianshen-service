package top.egon.cola.platform.tianquan.jianshen.processor;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.PermissionManifest;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PermissionManifestProcessorTest {

    @TempDir
    Path directory;

    private static final String NATIVE_PROTOCOL = """
            final class Example {
              private Example() {}
              static { if (System.nanoTime() != 0) throw new AssertionError("MUST NOT EXECUTE"); }
              @GetMapping("/.well-known/openid-configuration")
              @PermissionResource(key="demo.discovery", type=ResourceType.API, labelPage="demo", labelKey="discovery", access=ResourceAccess.PUBLIC)
              public static void discovery() { throw new AssertionError("MUST NOT EXECUTE"); }
            }
            """;

    @Test
    void exportsExplicitNativeProtocolWithoutMvcHeadOrLoadingClasses() throws Exception {
        var result = CompilerFixture.compile(directory, NATIVE_PROTOCOL,
                java.util.Map.of("metadataOnlyTypes", "demo.Example"));
        assertTrue(result.success(), result.diagnostics());
        assertEquals(List.of("GET"), result.manifest().resources().getFirst().target().get("methods"));
        assertEquals(List.of("/.well-known/openid-configuration"), result.manifest().resources().getFirst().target().get("paths"));
    }

    @Test
    void rejectsUnlistedAndMissingNativeProtocolHolders() throws Exception {
        var unlisted = CompilerFixture.compile(directory.resolve("unlisted"), NATIVE_PROTOCOL);
        assertFalse(unlisted.success());
        assertFalse(Files.exists(unlisted.fragmentPath()));
        var missing = CompilerFixture.compile(directory.resolve("missing"), NATIVE_PROTOCOL,
                java.util.Map.of("metadataOnlyTypes", "demo.Example,demo.Missing"));
        assertFalse(missing.success());
        assertTrue(missing.diagnostics().contains("not a compiled source"), missing.diagnostics());
        assertFalse(Files.exists(missing.fragmentPath()));
    }

    @Test
    void rejectsBeanOrInstantiableNativeProtocolHolders() throws Exception {
        List<String> invalid = List.of(
                "@RestController " + NATIVE_PROTOCOL,
                "@org.springframework.stereotype.Component " + NATIVE_PROTOCOL,
                NATIVE_PROTOCOL.replace("final class", "class"),
                NATIVE_PROTOCOL.replace("private Example()", "public Example()"),
                NATIVE_PROTOCOL.replace("private Example() {}", ""));
        for (int i = 0; i < invalid.size(); i++) {
            var result = CompilerFixture.compile(directory.resolve("case" + i), invalid.get(i),
                    java.util.Map.of("metadataOnlyTypes", "demo.Example"));
            assertFalse(result.success(), result.diagnostics());
            assertFalse(Files.exists(result.fragmentPath()));
        }
    }

    @Test
    void rejectsNativeInstanceMethodsProtectedAccessAndImplicitHttpMethods() throws Exception {
        List<String> invalid = List.of(
                NATIVE_PROTOCOL.replace("public static void", "public void"),
                NATIVE_PROTOCOL.replace("ResourceAccess.PUBLIC", "ResourceAccess.PROTECTED"),
                NATIVE_PROTOCOL.replace("@GetMapping", "@RequestMapping"),
                NATIVE_PROTOCOL.replace("void discovery()", "void discovery(String value)"));
        for (int i = 0; i < invalid.size(); i++) {
            var result = CompilerFixture.compile(directory.resolve("case" + i), invalid.get(i),
                    java.util.Map.of("metadataOnlyTypes", "demo.Example"));
            assertFalse(result.success(), result.diagnostics());
            assertFalse(Files.exists(result.fragmentPath()));
        }
    }

    @Test
    void exportsConstantsAndSourceMessagesWithoutRunningInitializers() throws Exception {
        var result = CompilerFixture.compile(directory, """
                @RestController @RequestMapping("/api")
                @PermissionDefinition(code="demo.read", meaning="Read demo records", labelPage="demo", labelKey="read")
                @PermissionMessage(pageCode="demo", key="read", defaultLocale="en", defaults=@LocalizedText(locale="en", text="Read"))
                class Example {
                  static final String KEY = "demo." + "read";
                  static { if (System.nanoTime() != 0) throw new AssertionError("MUST NOT EXECUTE"); }
                  @GetMapping({"/records", "/items"})
                  @PermissionResource(key=KEY, type=ResourceType.API, labelPage="demo", labelKey="read")
                  @RequiresPermissions(codes="demo.read")
                  String read() { return "ok"; }
                }
                """);
        assertTrue(result.success(), result.diagnostics());
        var manifest = result.manifest();
        assertEquals(PermissionManifest.SnapshotMode.PARTIAL, manifest.producer().snapshotMode());
        assertEquals(List.of("/api/items", "/api/records"), manifest.resources().getFirst().target().get("paths"));
        assertEquals(List.of("GET", "HEAD"), manifest.resources().getFirst().target().get("methods"));
        assertEquals("Read", manifest.messages().getFirst().defaults().get("en"));
    }

    @Test
    void combinesTypeMethodInterfaceAndComposedGroupsWithAnd() throws Exception {
        var result = CompilerFixture.compile(directory, """
                @Target(ElementType.METHOD) @Retention(RetentionPolicy.RUNTIME)
                @RequiresPermissions(mode=PermissionMode.ANY, codes={"demo.edit", "demo.read"})
                @interface ReadOrEdit {}
                @RequiresPermissions(codes="demo.base")
                interface Base<T> {
                  @GetMapping("/{id}")
                  @PermissionResource(key="demo.read", type=ResourceType.API, labelPage="demo", labelKey="read")
                  @ReadOrEdit
                  T read(T id);
                }
                @RestController @RequestMapping("/records")
                @PermissionReferences({"demo.base", "demo.tenant", "demo.read", "demo.edit"})
                @RequiresPermissions(codes="demo.tenant")
                class Example implements Base<String> {
                  public String read(String id) { return id; }
                }
                """);
        assertTrue(result.success(), result.diagnostics());
        var requirement = result.manifest().resources().getFirst().requirement();
        assertEquals(3, requirement.groups().size());
        assertTrue(requirement.allows(Set.of("demo.base", "demo.tenant", "demo.edit")));
        assertFalse(requirement.allows(Set.of("demo.tenant", "demo.edit")));
    }

    @Test
    void resolvesCustomAliasAndPreservesMappingConstraints() throws Exception {
        var result = CompilerFixture.compile(directory, """
                @Target(ElementType.METHOD) @Retention(RetentionPolicy.RUNTIME)
                @RequestMapping(method=RequestMethod.POST, produces="application/json", version="2")
                @interface Submit {
                  @org.springframework.core.annotation.AliasFor(annotation=RequestMapping.class, attribute="path")
                  String[] route() default {};
                }
                @RestController @RequestMapping(path="/api", method=RequestMethod.PUT, headers="X-Mode=a")
                class Example {
                  @Submit(route="/submit")
                  @PermissionResource(key="demo.submit", type=ResourceType.API, labelPage="demo", labelKey="submit", access=ResourceAccess.PUBLIC)
                  String submit() { return "ok"; }
                }
                """);
        assertTrue(result.success(), result.diagnostics());
        var target = result.manifest().resources().getFirst().target();
        assertEquals(List.of("POST", "PUT"), target.get("methods"));
        assertEquals(List.of("/api/submit"), target.get("paths"));
        assertEquals(List.of("X-Mode=a"), target.get("headers"));
        assertEquals(List.of("application/json"), target.get("produces"));
        assertEquals("2", target.get("version"));
    }

    @Test
    void exportsIndependentRecordFieldRulesOnce() throws Exception {
        var result = CompilerFixture.compile(directory, """
                @PermissionReferences({"demo.plain", "demo.masked", "demo.write"})
                record Example(
                  @PermissionResource(key="demo.email", type=ResourceType.FIELD, labelPage="demo", labelKey="email")
                  @FieldPermissions(valueType=PermissionManifest.JsonFieldType.STRING,
                    plainRead=@PermissionGroup(codes="demo.plain"), maskedRead=@PermissionGroup(codes="demo.masked"),
                    write=@PermissionGroup(codes="demo.write"), masker="EMAIL")
                  String email) {}
                """);
        assertTrue(result.success(), result.diagnostics());
        assertEquals(1, result.manifest().resources().size());
        var policy = result.manifest().resources().getFirst().fieldPolicy();
        assertEquals(List.of("demo.plain"), policy.plainRead().codes());
        assertEquals(List.of("demo.masked"), policy.maskedRead().codes());
        assertEquals(List.of("demo.write"), policy.write().codes());
    }

    @Test
    void omittedFieldOperationDeniesWithoutGrantingOtherOperations() throws Exception {
        var result = CompilerFixture.compile(directory, """
                @PermissionReferences("demo.read")
                class Example {
                  @PermissionResource(key="demo.name", type=ResourceType.FIELD, labelPage="demo", labelKey="name")
                  @FieldPermissions(valueType=PermissionManifest.JsonFieldType.STRING, plainRead=@PermissionGroup(codes="demo.read"))
                  String name;
                }
                """);
        assertTrue(result.success(), result.diagnostics());
        var policy = result.manifest().resources().getFirst().fieldPolicy();
        assertNotNull(policy.plainRead());
        assertNull(policy.maskedRead());
        assertNull(policy.write());
    }

    @Test
    void rejectsDuplicateResourceKeys() throws Exception {
        reject("""
                @RestController class Example {
                  @GetMapping("/a") @PermissionResource(key="demo.same", type=ResourceType.API, labelPage="demo", labelKey="a", access=ResourceAccess.PUBLIC)
                  String a() { return "a"; }
                  @GetMapping("/b") @PermissionResource(key="demo.same", type=ResourceType.API, labelPage="demo", labelKey="b", access=ResourceAccess.PUBLIC)
                  String b() { return "b"; }
                }
                """, "duplicate");
    }

    @Test
    void rejectsDynamicMapping() throws Exception {
        reject("""
                @RestController class Example {
                  @GetMapping("${route}/a") @PermissionResource(key="demo.a", type=ResourceType.API, labelPage="demo", labelKey="a", access=ResourceAccess.PUBLIC)
                  String a() { return "a"; }
                }
                """, "dynamic");
    }

    @Test
    void rejectsUndeclaredManagedEndpoint() throws Exception {
        reject("@RestController class Example { @GetMapping(\"/a\") String a() { return \"a\"; } }", "requires @PermissionResource");
    }

    @Test
    void rejectsPublicErasureOfInheritedPermission() throws Exception {
        reject("""
                @RestController @RequiresPermissions(codes="demo.base") @PermissionReferences("demo.base")
                class Example {
                  @GetMapping("/a") @PermissionResource(key="demo.a", type=ResourceType.API, labelPage="demo", labelKey="a", access=ResourceAccess.PUBLIC)
                  String a() { return "a"; }
                }
                """, "cannot erase");
    }

    @Test
    void rejectsEmptyPermissionGroupAndWrongFieldType() throws Exception {
        reject("""
                @RestController class Example {
                  @GetMapping("/a") @PermissionResource(key="demo.a", type=ResourceType.API, labelPage="demo", labelKey="a")
                  @RequiresPermissions(codes={}) String a() { return "a"; }
                }
                """, "must not be empty");
        var result = CompilerFixture.compile(directory.resolve("type"), """
                class Example {
                  @PermissionResource(key="demo.amount", type=ResourceType.FIELD, labelPage="demo", labelKey="amount")
                  @FieldPermissions(valueType=PermissionManifest.JsonFieldType.STRING) int amount;
                }
                """);
        assertFalse(result.success());
        assertTrue(result.diagnostics().contains("does not match"), result.diagnostics());
    }

    @Test
    void rejectsAmbiguousInheritedMapping() throws Exception {
        reject("""
                interface A { @GetMapping("/a") String get(); }
                interface B { @GetMapping("/b") String get(); }
                @RestController class Example implements A,B {
                  @PermissionResource(key="demo.a", type=ResourceType.API, labelPage="demo", labelKey="a", access=ResourceAccess.PUBLIC)
                  public String get() { return "a"; }
                }
                """, "ambiguous");
    }

    @Test
    void invalidCompilationRemovesPreviousFragment() throws Exception {
        var first = CompilerFixture.compile(directory, """
                @RestController class Example {
                  @GetMapping("/a") @PermissionResource(key="demo.a", type=ResourceType.API, labelPage="demo", labelKey="a", access=ResourceAccess.PUBLIC)
                  String a() { return "a"; }
                }
                """);
        assertTrue(first.success(), first.diagnostics());
        assertTrue(Files.exists(first.fragmentPath()));
        var second = CompilerFixture.compile(directory, "@RestController class Example { @GetMapping(\"/a\") String a() { return \"a\"; } }");
        assertFalse(second.success());
        assertFalse(Files.exists(second.fragmentPath()));
    }

    @Test
    void exportsExplicitJacksonWireTypesAndStandardScalars() throws Exception {
        var result = CompilerFixture.compile(directory, """
                enum State { ACTIVE }
                class Example {
                  @PermissionResource(key="demo.time", type=ResourceType.FIELD, labelPage="demo", labelKey="time")
                  @FieldPermissions(valueType=PermissionManifest.JsonFieldType.STRING)
                  @com.fasterxml.jackson.annotation.JsonFormat(shape=com.fasterxml.jackson.annotation.JsonFormat.Shape.STRING)
                  java.time.LocalDateTime time;
                  @PermissionResource(key="demo.id", type=ResourceType.FIELD, labelPage="demo", labelKey="id")
                  @FieldPermissions(valueType=PermissionManifest.JsonFieldType.STRING)
                  @com.fasterxml.jackson.databind.annotation.JsonSerialize(using=com.fasterxml.jackson.databind.ser.std.ToStringSerializer.class)
                  Long id;
                  @PermissionResource(key="demo.state", type=ResourceType.FIELD, labelPage="demo", labelKey="state")
                  @FieldPermissions(valueType=PermissionManifest.JsonFieldType.STRING) State state;
                  @PermissionResource(key="demo.uri", type=ResourceType.FIELD, labelPage="demo", labelKey="uri")
                  @FieldPermissions(valueType=PermissionManifest.JsonFieldType.STRING) java.net.URI uri;
                }
                """);
        assertTrue(result.success(), result.diagnostics());
        assertEquals(4, result.manifest().resources().size());
        assertTrue(result.manifest().resources().stream().allMatch(resource ->
                resource.fieldPolicy().valueType() == PermissionManifest.JsonFieldType.STRING));
    }

    @Test
    void rejectsAmbiguousTemporalAndCustomSerializerWireTypes() throws Exception {
        var temporal = CompilerFixture.compile(directory.resolve("time"), """
                class Example {
                  @PermissionResource(key="demo.time", type=ResourceType.FIELD, labelPage="demo", labelKey="time")
                  @FieldPermissions(valueType=PermissionManifest.JsonFieldType.STRING) java.time.Instant time;
                }
                """);
        assertFalse(temporal.success());
        assertTrue(temporal.diagnostics().contains("explicit @JsonFormat"), temporal.diagnostics());
        var serializer = CompilerFixture.compile(directory.resolve("custom"), """
                class Example {
                  @PermissionResource(key="demo.id", type=ResourceType.FIELD, labelPage="demo", labelKey="id")
                  @FieldPermissions(valueType=PermissionManifest.JsonFieldType.STRING)
                  @com.fasterxml.jackson.databind.annotation.JsonSerialize(using=com.fasterxml.jackson.databind.ser.std.NumberSerializer.class)
                  Long id;
                }
                """);
        assertFalse(serializer.success());
        assertTrue(serializer.diagnostics().contains("custom FIELD serializer"), serializer.diagnostics());
    }

    @Test
    void explicitPublicFieldsRemainSeparateFromProtectedFieldPolicies() throws Exception {
        var result = CompilerFixture.compile(directory.resolve("public"), """
                record Example(
                  @PermissionResource(key="demo.locale", type=ResourceType.FIELD, labelPage="demo", labelKey="locale", access=ResourceAccess.PUBLIC)
                  String locale,
                  @PermissionResource(key="demo.internal", type=ResourceType.FIELD, labelPage="demo", labelKey="internal", access=ResourceAccess.INTERNAL)
                  String internal) { }
                """);
        assertTrue(result.success(), result.diagnostics());
        assertEquals(2, result.manifest().resources().size());
        assertTrue(result.manifest().resources().stream().allMatch(resource -> resource.fieldPolicy() == null));
        var invalid = CompilerFixture.compile(directory.resolve("invalid"), """
                class Example {
                  @PermissionResource(key="demo.locale", type=ResourceType.FIELD, labelPage="demo", labelKey="locale", access=ResourceAccess.PUBLIC)
                  @FieldPermissions(valueType=PermissionManifest.JsonFieldType.STRING) String locale;
                }
                """);
        assertFalse(invalid.success());
        assertTrue(invalid.diagnostics().contains("cannot erase field rules"), invalid.diagnostics());
    }

    @Test
    void resolvesScalarJsonValueWithoutExecutingEnumCode() throws Exception {
        var result = CompilerFixture.compile(directory.resolve("value"), """
                enum State { ACTIVE;
                  @com.fasterxml.jackson.annotation.JsonValue public String value() { throw new AssertionError("MUST NOT EXECUTE"); }
                }
                class Example {
                  @PermissionResource(key="demo.state", type=ResourceType.FIELD, labelPage="demo", labelKey="state")
                  @FieldPermissions(valueType=PermissionManifest.JsonFieldType.STRING) State state;
                }
                """);
        assertTrue(result.success(), result.diagnostics());
        assertEquals(PermissionManifest.JsonFieldType.STRING, result.manifest().resources().getFirst().fieldPolicy().valueType());
        var unknown = CompilerFixture.compile(directory.resolve("unknown-value"), """
                enum State { ACTIVE;
                  @com.fasterxml.jackson.annotation.JsonValue public Object value() { return "dynamic"; }
                }
                class Example {
                  @PermissionResource(key="demo.state", type=ResourceType.FIELD, labelPage="demo", labelKey="state")
                  @FieldPermissions(valueType=PermissionManifest.JsonFieldType.STRING) State state;
                }
                """);
        assertFalse(unknown.success());
        assertTrue(unknown.diagnostics().contains("supported JSON scalar"), unknown.diagnostics());
    }

    @Test
    void resolvesInheritedJsonValueButRejectsMultipleEffectiveValues() throws Exception {
        var result = CompilerFixture.compile(directory.resolve("inherited-value"), """
                class Parent { @com.fasterxml.jackson.annotation.JsonValue public String value() { return "a"; } }
                class Child extends Parent { @Override public String value() { return "b"; } }
                class Example {
                  @PermissionResource(key="demo.value", type=ResourceType.FIELD, labelPage="demo", labelKey="value")
                  @FieldPermissions(valueType=PermissionManifest.JsonFieldType.STRING) Child value;
                }
                """);
        assertTrue(result.success(), result.diagnostics());
        var ambiguous = CompilerFixture.compile(directory.resolve("multiple-values"), """
                class Value {
                  @com.fasterxml.jackson.annotation.JsonValue public String first() { return "a"; }
                  @com.fasterxml.jackson.annotation.JsonValue public int second() { return 2; }
                }
                class Example {
                  @PermissionResource(key="demo.value", type=ResourceType.FIELD, labelPage="demo", labelKey="value")
                  @FieldPermissions(valueType=PermissionManifest.JsonFieldType.STRING) Value value;
                }
                """);
        assertFalse(ambiguous.success());
        assertTrue(ambiguous.diagnostics().contains("one static scalar type"), ambiguous.diagnostics());
    }

    @Test
    void recordFieldsUsePropagatedJacksonAliasAndTemporalShape() throws Exception {
        var result = CompilerFixture.compile(directory.resolve("record-jackson"), """
                record Example(
                  @PermissionResource(key="demo.created", type=ResourceType.FIELD, labelPage="demo", labelKey="created")
                  @FieldPermissions(valueType=PermissionManifest.JsonFieldType.STRING)
                  @com.fasterxml.jackson.annotation.JsonProperty("created_at")
                  @com.fasterxml.jackson.annotation.JsonFormat(shape=com.fasterxml.jackson.annotation.JsonFormat.Shape.STRING)
                  java.time.Instant createdAt) { }
                """);
        assertTrue(result.success(), result.diagnostics());
        assertEquals(1, result.manifest().resources().size());
        assertEquals("created_at", result.manifest().resources().getFirst().target().get("property"));
        assertEquals(PermissionManifest.JsonFieldType.STRING, result.manifest().resources().getFirst().fieldPolicy().valueType());
    }

    @Test
    void emptyMethodPathPreservesTheClassPathWithoutAddingATrailingSlash() throws Exception {
        var result = CompilerFixture.compile(directory.resolve("empty-suffix"), """
                @RestController @RequestMapping("/api") class Example {
                  @GetMapping
                  @PermissionResource(key="demo.root", type=ResourceType.API, labelPage="demo", labelKey="root", access=ResourceAccess.PUBLIC)
                  String root() { return "root"; }
                  @GetMapping("/")
                  @PermissionResource(key="demo.slash", type=ResourceType.API, labelPage="demo", labelKey="slash", access=ResourceAccess.PUBLIC)
                  String slash() { return "slash"; }
                }
                """);
        assertTrue(result.success(), result.diagnostics());
        assertEquals(List.of("/api"), result.manifest().resources().stream().filter(resource -> resource.key().equals("demo.root"))
                .findFirst().orElseThrow().target().get("paths"));
        assertEquals(List.of("/api/"), result.manifest().resources().stream().filter(resource -> resource.key().equals("demo.slash"))
                .findFirst().orElseThrow().target().get("paths"));
        var root = CompilerFixture.compile(directory.resolve("explicit-root"), """
                @RestController class Example {
                  @GetMapping("/")
                  @PermissionResource(key="demo.root", type=ResourceType.API, labelPage="demo", labelKey="root", access=ResourceAccess.PUBLIC)
                  String root() { return "root"; }
                }
                """);
        assertTrue(root.success(), root.diagnostics());
        assertEquals(List.of("/"), root.manifest().resources().getFirst().target().get("paths"));
        var unresolvedRoot = CompilerFixture.compile(directory.resolve("empty-root"), """
                @RestController class Example {
                  @GetMapping
                  @PermissionResource(key="demo.root", type=ResourceType.API, labelPage="demo", labelKey="root", access=ResourceAccess.PUBLIC)
                  String root() { return "root"; }
                }
                """);
        assertFalse(unresolvedRoot.success());
        assertTrue(unresolvedRoot.diagnostics().contains("explicit '/'"), unresolvedRoot.diagnostics());
    }

    @Test
    void binaryArraysMatchJacksonBase64EvenWithArrayShape() throws Exception {
        var wire = new com.fasterxml.jackson.databind.ObjectMapper().valueToTree(new BinaryShape());
        assertTrue(wire.get("plain").isBinary());
        assertEquals("AQI=", wire.get("plain").asText());
        assertEquals(wire.get("plain"), wire.get("array"));
        for (String shape : List.of("", "@com.fasterxml.jackson.annotation.JsonFormat(shape=com.fasterxml.jackson.annotation.JsonFormat.Shape.ARRAY)")) {
            String source = """
                    class Example {
                      @PermissionResource(key="demo.content", type=ResourceType.FIELD, labelPage="demo", labelKey="content")
                      @FieldPermissions(valueType=PermissionManifest.JsonFieldType.%s)
                      %s byte[] content;
                    }
                    """;
            var result = CompilerFixture.compile(directory.resolve(shape.isEmpty() ? "binary" : "binary-array-shape"),
                    source.formatted("STRING", shape));
            assertTrue(result.success(), result.diagnostics());
            assertEquals(PermissionManifest.JsonFieldType.STRING, result.manifest().resources().getFirst().fieldPolicy().valueType());
            var wrong = CompilerFixture.compile(directory.resolve(shape.isEmpty() ? "wrong-binary" : "wrong-binary-array-shape"),
                    source.formatted("ARRAY", shape));
            assertFalse(wrong.success());
            assertTrue(wrong.diagnostics().contains("serializes as STRING"), wrong.diagnostics());
        }
    }

    public static final class BinaryShape {
        public byte[] plain = {1, 2};
        @com.fasterxml.jackson.annotation.JsonFormat(shape = com.fasterxml.jackson.annotation.JsonFormat.Shape.ARRAY)
        public byte[] array = {1, 2};
    }

    private void reject(String source, String diagnostic) throws Exception {
        var result = CompilerFixture.compile(directory, source);
        assertFalse(result.success(), result.diagnostics());
        assertTrue(result.diagnostics().contains(diagnostic), result.diagnostics());
        assertFalse(Files.exists(result.fragmentPath()));
    }
}
