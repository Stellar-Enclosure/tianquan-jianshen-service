package top.egon.cola.platform.tianquan.jianshen.contract;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.PermissionManifestReader;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static top.egon.cola.platform.tianquan.jianshen.contract.PermissionCanonicalizationTest.fixture;
import static top.egon.cola.platform.tianquan.jianshen.contract.PermissionCanonicalizationTest.list;
import static top.egon.cola.platform.tianquan.jianshen.contract.PermissionCanonicalizationTest.object;

class PermissionManifestSchemaTest {

    private final PermissionManifestReader reader = new PermissionManifestReader();

    @Test
    void canonicalSchemaIsAvailableAsAMainJarResource() throws Exception {
        try (var input = getClass().getResourceAsStream("/permission-manifest/schema-v1.json")) {
            assertNotNull(input);
            var schema = new ObjectMapper().readTree(input);
            assertEquals("1.0", schema.path("properties").path("schemaVersion").path("const").textValue());
            assertFalse(schema.path("additionalProperties").booleanValue());
            assertEquals(7, schema.path("$defs").path("resource").path("properties").path("type").path("enum").size());
        }
    }

    @Test
    void rejectsUnknownPropertiesAndEnvironmentOrCentreIdsInSourceManifest() throws Exception {
        for (String name : List.of("resourceIds", "environment", "artifactDigest", "tenantId")) {
            var value = fixture();
            value.put(name, "untrusted");
            assertThrows(IllegalArgumentException.class, () -> reader.read(value), name);
        }
        var nested = fixture();
        object(list(nested.get("resources")).getFirst()).put("resourceId", "9001");
        assertThrows(IllegalArgumentException.class, () -> reader.read(nested));
    }

    @Test
    void fullScanCannotHideMissingModulesOrImplicitEmptyProducer() throws Exception {
        var partial = fixture();
        object(partial.get("producer")).put("expectedModules", List.of("admin", "rpc"));
        assertThrows(IllegalArgumentException.class, () -> reader.read(partial));
        object(partial.get("producer")).put("snapshotMode", "PARTIAL");
        assertDoesNotThrow(() -> reader.read(partial));
        var empty = fixture();
        for (String key : List.of("resources", "permissionDefinitions", "messages")) empty.put(key, List.of());
        assertThrows(IllegalArgumentException.class, () -> reader.read(empty));
    }

    @Test
    void referencesMustBeDeclaredAndTypeUnsafeMaskersCannotRegister() throws Exception {
        var unknown = fixture();
        object(object(list(unknown.get("resources")).getFirst()).get("requirement"))
                .put("codes", List.of("order:unknown"));
        assertThrows(IllegalArgumentException.class, () -> reader.read(unknown));
        var masked = fixture();
        var policy = object(object(list(masked.get("resources")).get(1)).get("fieldPolicy"));
        policy.put("maskedRead", Map.of("mode", "ALL", "codes", List.of("order:read")));
        policy.put("masker", "FIXED");
        assertThrows(IllegalArgumentException.class, () -> reader.read(masked));
    }

    @Test
    void caseOnlyResourceCollisionAndWrongOwnerPrefixFail() throws Exception {
        var duplicate = fixture();
        object(list(duplicate.get("resources")).get(1)).put("key", "Order.Api.Detail");
        assertThrows(IllegalArgumentException.class, () -> reader.read(duplicate));
        var wrongOwner = fixture();
        object(wrongOwner.get("producer")).put("ownedKeyPrefixes", List.of("another."));
        assertThrows(IllegalArgumentException.class, () -> reader.read(wrongOwner));
    }

    @Test
    void multipleMappingsAreBoundedSortedAndDefensivelyCopied() throws Exception {
        var source = fixture();
        var paths = new java.util.ArrayList<>(List.of("/orders/{id}", "/order/{id}"));
        object(list(source.get("resources")).getFirst()).put("target",
                Map.of("paths", paths, "methods", List.of("GET", "HEAD")));
        var resource = reader.read(source).resources().getFirst();
        assertEquals(List.of("/order/{id}", "/orders/{id}"), resource.target().get("paths"));
        paths.clear();
        assertEquals(2, ((List<?>) resource.target().get("paths")).size());
        object(list(source.get("resources")).getFirst()).put("target", Map.of("paths", List.of()));
        assertThrows(IllegalArgumentException.class, () -> reader.read(source));
    }
    @Test
    void publicAndInternalFieldsRequireExplicitClassificationWithoutProtectedRules() throws Exception {
        for (String access : List.of("PUBLIC", "INTERNAL")) {
            var source = fixture();
            var field = object(list(source.get("resources")).get(1));
            field.put("access", access);
            assertThrows(IllegalArgumentException.class, () -> reader.read(source));
            field.remove("fieldPolicy");
            assertDoesNotThrow(() -> reader.read(source));
            field.put("access", "PROTECTED");
            assertThrows(IllegalArgumentException.class, () -> reader.read(source));
            field.remove("access");
            assertThrows(IllegalArgumentException.class, () -> reader.read(source));
        }
        try (var input = getClass().getResourceAsStream("/permission-manifest/schema-v1.json")) {
            var exempt = new ObjectMapper().readTree(input).path("$defs").path("resource").path("allOf").get(1)
                    .path("if").path("not").path("properties").path("access").path("enum");
            assertEquals(List.of("PUBLIC", "INTERNAL"), new ObjectMapper().convertValue(exempt, List.class));
        }
    }

}
