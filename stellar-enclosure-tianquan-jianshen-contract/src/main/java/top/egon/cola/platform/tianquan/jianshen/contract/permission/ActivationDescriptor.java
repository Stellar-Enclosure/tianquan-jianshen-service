package top.egon.cola.platform.tianquan.jianshen.contract.permission;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;

public record ActivationDescriptor(
        CatalogScope scope,
        String activationVersion,
        String operationId,
        String policyVersion,
        @com.fasterxml.jackson.annotation.JsonFormat(shape = com.fasterxml.jackson.annotation.JsonFormat.Shape.STRING) Instant createdAt,
        List<ProducerVersion> producers
) {

    public ActivationDescriptor {
        Objects.requireNonNull(scope, "scope");
        activationVersion = ManifestChecks.decimal(activationVersion, "activationVersion", false);
        if (operationId == null || !UUID.fromString(operationId).toString().equals(operationId)) {
            throw new IllegalArgumentException("operationId must be a canonical UUID");
        }
        policyVersion = ManifestChecks.decimal(policyVersion, "policyVersion", true);
        Objects.requireNonNull(createdAt, "createdAt");
        producers = ManifestChecks.sortedUnique(producers, "producers", 256, ProducerVersion::producerId);
        if (producers.isEmpty()) throw new IllegalArgumentException("activation needs a complete producer set");
    }

    public ProducerVersion requireProducer(String producerId, String producerVersion) {
        return producers.stream().filter(producer -> producer.producerId().equals(producerId)
                && producer.producerVersion().equals(producerVersion)).findFirst()
                .orElseThrow(() -> new IllegalArgumentException("producer version is not in this activation"));
    }

    public Map<String, Object> toMap() {
        return Map.of("scope", ManifestRegistrationRequest.targetMap(scope), "activationVersion", activationVersion,
                "operationId", operationId, "policyVersion", policyVersion, "createdAt", createdAt.toString(),
                "producers", producers.stream().map(producer -> Map.of(
                        "producerId", producer.producerId(), "producerVersion", producer.producerVersion(),
                        "sourceVersion", producer.sourceVersion(), "qualificationId", producer.qualificationId(),
                        "artifactDigest", producer.artifactDigest(), "digests", Map.of(
                                "policyDigest", producer.digests().policyDigest(),
                                "metadataDigest", producer.digests().metadataDigest(),
                                "manifestDigest", producer.digests().manifestDigest()))).toList());
    }

    public String canonicalize() {
        String result = CanonicalJson.write(toMap());
        if (result.getBytes(java.nio.charset.StandardCharsets.UTF_8).length > PermissionManifest.MAX_BYTES) {
            throw new IllegalArgumentException("activation descriptor exceeds its byte limit");
        }
        return result;
    }

    public String digest() {
        // Keep the byte limit identical for wire, durable storage and remote projection consumers.
        canonicalize();
        return CanonicalJson.digest(toMap());
    }

    public record ProducerVersion(
            String producerId,
            String producerVersion,
            String sourceVersion,
            ManifestDigests digests,
            String qualificationId,
            String artifactDigest
    ) {
        public ProducerVersion {
            producerId = ManifestChecks.identifier(producerId, "producerId", 128);
            producerVersion = ManifestChecks.decimal(producerVersion, "producerVersion", false);
            sourceVersion = ManifestChecks.hash(sourceVersion, "sourceVersion");
            Objects.requireNonNull(digests, "digests");
            qualificationId = ManifestChecks.decimal(qualificationId, "qualificationId", false);
            artifactDigest = ManifestChecks.hash(artifactDigest, "artifactDigest");
            if (!sourceVersion.equals(digests.manifestDigest())) {
                throw new IllegalArgumentException("sourceVersion does not match manifestDigest");
            }
        }
    }
}
