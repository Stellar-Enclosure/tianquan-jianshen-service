package top.egon.cola.platform.tianquan.jianshen.contract;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.CanonicalJson;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.PermissionManifestCanonicalizer;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.PermissionManifestReader;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class PermissionCanonicalizationTest {

    private final PermissionManifestReader reader = new PermissionManifestReader();
    private final PermissionManifestCanonicalizer canonicalizer = new PermissionManifestCanonicalizer();

    @Test
    void matchesIndependentUtf8FixtureAndRoundTripsCanonicalContent() throws Exception {
        var manifest = reader.read(fixture());
        var expected = read("/permission-contract/canonical-v1.json");
        assertEquals(expected.get("canonical"), canonicalizer.canonicalize(manifest));
        var digests = canonicalizer.digests(manifest);
        assertEquals(expected.get("policyDigest"), digests.policyDigest());
        assertEquals(expected.get("metadataDigest"), digests.metadataDigest());
        assertEquals(expected.get("manifestDigest"), digests.manifestDigest());
        assertEquals(digests, canonicalizer.digests(reader.read(canonicalizer.toMap(manifest))));
    }

    @Test
    void provenanceAndTranslationsDoNotChangeThePolicyDigest() throws Exception {
        var original = canonicalizer.digests(reader.read(fixture()));
        var provenance = fixture();
        object(provenance.get("artifact")).put("buildId", "build-2");
        var changedBuild = canonicalizer.digests(reader.read(provenance));
        assertEquals(original.policyDigest(), changedBuild.policyDigest());
        assertEquals(original.metadataDigest(), changedBuild.metadataDigest());
        assertNotEquals(original.manifestDigest(), changedBuild.manifestDigest());

        var translation = fixture();
        object(object(list(translation.get("messages")).getFirst()).get("defaults")).put("zh-CN", "新显示名称");
        var changedText = canonicalizer.digests(reader.read(translation));
        assertEquals(original.policyDigest(), changedText.policyDigest());
        assertNotEquals(original.metadataDigest(), changedText.metadataDigest());
    }

    @Test
    void fieldWriteExpansionChangesPolicyButNotDisplayMetadata() throws Exception {
        var original = canonicalizer.digests(reader.read(fixture()));
        var expanded = fixture();
        var field = object(list(expanded.get("resources")).get(1));
        object(object(field.get("fieldPolicy")).get("write")).put("codes", List.of("order:read"));
        var changed = canonicalizer.digests(reader.read(expanded));
        assertNotEquals(original.policyDigest(), changed.policyDigest());
        assertEquals(original.metadataDigest(), changed.metadataDigest());
    }

    @Test
    void canonicalWriterRejectsAmbiguousNumbersAndMalformedUnicode() {
        assertEquals("{\"a\":\"金额\\n\",\"z\":1}", CanonicalJson.write(Map.of("z", 1, "a", "金额\n")));
        assertThrows(IllegalArgumentException.class, () -> CanonicalJson.write(1.0));
        assertThrows(IllegalArgumentException.class, () -> CanonicalJson.write(Double.NaN));
        assertThrows(IllegalArgumentException.class, () -> CanonicalJson.write(Long.MAX_VALUE));
        assertThrows(IllegalArgumentException.class, () -> CanonicalJson.write("\uD800"));
    }

    static Map<String, Object> fixture() throws Exception {
        return read("/permission-contract/manifest-v1.json");
    }

    private static Map<String, Object> read(String path) throws Exception {
        try (var input = PermissionCanonicalizationTest.class.getResourceAsStream(path)) {
            return new ObjectMapper().readValue(input, new TypeReference<>() { });
        }
    }

    @SuppressWarnings("unchecked")
    static Map<String, Object> object(Object value) { return (Map<String, Object>) value; }

    @SuppressWarnings("unchecked")
    static List<Object> list(Object value) { return (List<Object>) value; }
}
