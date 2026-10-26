package top.egon.cola.platform.tianquan.jianshen.contract.permission;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class ManifestRegistrationContractTest {

    @Test
    void planRejectsTargetApplicationMismatchAndBindsAllTargetCoordinates() throws Exception {
        PermissionManifest manifest = fixture();
        CatalogScope scope = scope(manifest, "test");
        var plan = new ManifestRegistrationRequest.Plan(scope, manifest, "0", "0");
        var other = new ManifestRegistrationRequest.Plan(scope(manifest, "prod"), manifest, "0", "0");
        assertNotEquals(plan.requestDigest(), other.requestDigest());
        assertThrows(IllegalArgumentException.class, () -> new ManifestRegistrationRequest.Plan(
                new CatalogScope("1", "2", "wrong", "wrong", "default", "test"), manifest, "0", "0"));
    }

    @Test
    void applyDigestBindsPlanAndOperationAndExpectedRevisions() throws Exception {
        PermissionManifest manifest = fixture();
        ManifestDigests hashes = new PermissionManifestCanonicalizer().digests(manifest);
        var first = new ManifestRegistrationRequest.Apply(scope(manifest, "test"), manifest.producer().id(), "3",
                "00000000-0000-0000-0000-000000000001", hashes, "0", "0");
        var second = new ManifestRegistrationRequest.Apply(first.target(), first.producerId(), "4", first.operationId(), hashes, "0", "0");
        assertNotEquals(first.requestDigest(), second.requestDigest());
        assertThrows(IllegalArgumentException.class, () -> new ManifestRegistrationRequest.Apply(first.target(), first.producerId(),
                "03", first.operationId(), hashes, "0", "0"));
    }

    @Test
    void descriptorCanonicalMapIsStableAndBindsProducerProofs() {
        ManifestDigests hashes = new ManifestDigests("a".repeat(64), "b".repeat(64), "c".repeat(64));
        var a = new ActivationDescriptor.ProducerVersion("api", "1", hashes.manifestDigest(), hashes, "5", "d".repeat(64));
        var b = new ActivationDescriptor.ProducerVersion("web", "2", hashes.manifestDigest(), hashes, "6", "e".repeat(64));
        CatalogScope scope = new CatalogScope("1", "2", "biz", "app", "default", "test");
        var first = new ActivationDescriptor(scope, "1", "00000000-0000-0000-0000-000000000001", "3",
                Instant.parse("2026-10-25T00:00:00Z"), List.of(b, a));
        var second = new ActivationDescriptor(scope, "1", first.operationId(), "3", first.createdAt(), List.of(a, b));
        assertEquals(first.canonicalize(), second.canonicalize());
        assertEquals(first.digest(), CanonicalJson.digest(first.toMap()));
        assertEquals("2026-10-25T00:00:00Z", first.toMap().get("createdAt"));
        var changed = new ActivationDescriptor(scope, "1", first.operationId(), "4", first.createdAt(), List.of(a, b));
        assertNotEquals(first.digest(), changed.digest());
    }

    @Test
    void originalReceiptCountsAndIdsCannotDrift() {
        CatalogScope scope = new CatalogScope("1", "2", "biz", "app", "default", "test");
        ManifestDigests hashes = new ManifestDigests("a".repeat(64), "b".repeat(64), "c".repeat(64));
        assertThrows(IllegalArgumentException.class, () -> new ManifestRegistrationReceipt(
                "00000000-0000-0000-0000-000000000001", "1", scope, "api", "1", hashes,
                Map.of("demo.a", "4"), Map.of(), 0, 0, 0, Instant.EPOCH));
    }

    private CatalogScope scope(PermissionManifest manifest, String environment) {
        return new CatalogScope("1", "2", manifest.application().businessCode(), manifest.application().applicationCode(), "default", environment);
    }

    private PermissionManifest fixture() throws Exception {
        try (var input = getClass().getResourceAsStream("/permission-contract/manifest-v1.json")) {
            Map<String, Object> data = new ObjectMapper().readValue(input, new TypeReference<>() { });
            return new PermissionManifestReader().read(data);
        }
    }
}
