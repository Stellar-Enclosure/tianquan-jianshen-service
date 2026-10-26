package top.egon.cola.platform.tianquan.jianshen.contract.permission;

import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;

/** A complete, explicitly qualified producer selection; an omitted producer is never retired implicitly. */
public record CatalogActivationRequest(CatalogScope target, String operationId, String expectedActiveRevision,
                                       List<Selection> producers) {
    public CatalogActivationRequest {
        Objects.requireNonNull(target, "target");
        if (operationId == null || !UUID.fromString(operationId).toString().equals(operationId)) {
            throw new IllegalArgumentException("operationId must be a canonical UUID");
        }
        expectedActiveRevision = ManifestChecks.decimal(expectedActiveRevision, "expectedActiveRevision", true);
        producers = ManifestChecks.sortedUnique(producers, "producers", 256, Selection::producerId);
        if (producers.isEmpty()) throw new IllegalArgumentException("activation requires a complete producer set");
    }

    public String requestDigest() {
        return CanonicalJson.digest(Map.of("target", ManifestRegistrationRequest.targetMap(target), "operationId", operationId,
                "expectedActiveRevision", expectedActiveRevision, "producers", producers.stream().map(Selection::toMap).toList()));
    }

    public record Selection(String producerId, String producerVersion, String qualificationId) {
        public Selection {
            producerId = ManifestChecks.identifier(producerId, "producerId", 128);
            producerVersion = ManifestChecks.decimal(producerVersion, "producerVersion", false);
            qualificationId = ManifestChecks.decimal(qualificationId, "qualificationId", false);
        }

        public Map<String, Object> toMap() {
            return Map.of("producerId", producerId, "producerVersion", producerVersion, "qualificationId", qualificationId);
        }
    }
}
