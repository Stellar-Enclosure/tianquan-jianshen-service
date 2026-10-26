package top.egon.cola.platform.tianquan.jianshen.contract.permission;

import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;

/** Registration envelopes bind canonical content to an explicit existing catalog target. */
public final class ManifestRegistrationRequest {

    private ManifestRegistrationRequest() { }

    public record Target(CatalogScope target, String producerId) {
        public Target {
            Objects.requireNonNull(target, "target");
            producerId = ManifestChecks.identifier(producerId, "producerId", 128);
        }
    }

    public record Plan(CatalogScope target, PermissionManifest manifest,
                       String expectedProducerRevision, String expectedActiveRevision) {
        public Plan {
            Objects.requireNonNull(target, "target");
            Objects.requireNonNull(manifest, "manifest");
            expectedProducerRevision = ManifestChecks.decimal(expectedProducerRevision, "expectedProducerRevision", true);
            expectedActiveRevision = ManifestChecks.decimal(expectedActiveRevision, "expectedActiveRevision", true);
            if (!target.businessCode().equals(manifest.application().businessCode())
                    || !target.applicationCode().equals(manifest.application().applicationCode())) {
                throw new IllegalArgumentException("manifest application differs from target");
            }
            if (new PermissionManifestCanonicalizer().canonicalize(manifest).getBytes(StandardCharsets.UTF_8).length
                    > PermissionManifest.MAX_BYTES) throw new IllegalArgumentException("manifest exceeds canonical byte limit");
        }

        public String requestDigest() {
            return CanonicalJson.digest(Map.of("target", targetMap(target),
                    "manifestDigest", new PermissionManifestCanonicalizer().digests(manifest).manifestDigest(),
                    "expectedProducerRevision", expectedProducerRevision, "expectedActiveRevision", expectedActiveRevision));
        }
    }

    public record Apply(CatalogScope target, String producerId, String planId, String operationId,
                        ManifestDigests digests, String expectedProducerRevision, String expectedActiveRevision) {
        public Apply {
            Objects.requireNonNull(target, "target");
            producerId = ManifestChecks.identifier(producerId, "producerId", 128);
            planId = ManifestChecks.decimal(planId, "planId", false);
            if (operationId == null || !UUID.fromString(operationId).toString().equals(operationId)) {
                throw new IllegalArgumentException("operationId must be a canonical UUID");
            }
            Objects.requireNonNull(digests, "digests");
            expectedProducerRevision = ManifestChecks.decimal(expectedProducerRevision, "expectedProducerRevision", true);
            expectedActiveRevision = ManifestChecks.decimal(expectedActiveRevision, "expectedActiveRevision", true);
        }

        public String requestDigest() {
            return CanonicalJson.digest(Map.of("target", targetMap(target), "producerId", producerId,
                    "planId", planId, "operationId", operationId,
                    "digests", Map.of("manifestDigest", digests.manifestDigest(), "policyDigest", digests.policyDigest(),
                            "metadataDigest", digests.metadataDigest()),
                    "expectedProducerRevision", expectedProducerRevision, "expectedActiveRevision", expectedActiveRevision));
        }
    }

    public static Map<String, Object> targetMap(CatalogScope target) {
        return Map.of("catalogScopeId", target.catalogScopeId(), "tenantId", target.tenantId(),
                "businessCode", target.businessCode(), "applicationCode", target.applicationCode(),
                "namespaceCode", target.namespaceCode(), "environment", target.environment());
    }
}
