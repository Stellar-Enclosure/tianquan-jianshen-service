package top.egon.cola.platform.tianquan.jianshen.contract.permission;

import java.time.Instant;
import java.util.Map;
import java.util.Objects;

/** An attestation is accepted only from the exact SQL-granted deployment authority. */
public record DeploymentQualificationRequest(CatalogScope target, String producerId, String producerVersion,
                                              String artifactDigest, String manifestDigest, String policyDigest,
                                              String pipelineId, String buildId, String sourceRef, String commit,
                                              String deploymentId, Readiness readiness) {
    public DeploymentQualificationRequest {
        Objects.requireNonNull(target, "target");
        producerId = ManifestChecks.identifier(producerId, "producerId", 128);
        producerVersion = ManifestChecks.decimal(producerVersion, "producerVersion", false);
        artifactDigest = ManifestChecks.hash(artifactDigest, "artifactDigest");
        manifestDigest = ManifestChecks.hash(manifestDigest, "manifestDigest");
        policyDigest = ManifestChecks.hash(policyDigest, "policyDigest");
        pipelineId = text(pipelineId, "pipelineId");
        buildId = text(buildId, "buildId");
        sourceRef = text(sourceRef, "sourceRef");
        deploymentId = text(deploymentId, "deploymentId");
        if (commit == null || !commit.matches("(?:[0-9a-f]{40}|[0-9a-f]{64})")) throw new IllegalArgumentException("invalid commit");
        Objects.requireNonNull(readiness, "readiness");
        if (!artifactDigest.equals(readiness.artifactDigest()) || !manifestDigest.equals(readiness.manifestDigest())
                || !policyDigest.equals(readiness.policyDigest())) throw new IllegalArgumentException("readiness artifact mismatch");
    }

    private static String text(String value, String name) {
        if (value == null || value.isBlank() || value.length() > 256 || !value.equals(value.strip())
                || value.codePoints().anyMatch(Character::isISOControl)) throw new IllegalArgumentException("invalid " + name);
        return value;
    }

    public record Readiness(String artifactDigest, String manifestDigest, String policyDigest,
                            boolean componentsReady, boolean dependenciesReady, boolean policyLoaded,
                            @com.fasterxml.jackson.annotation.JsonFormat(shape = com.fasterxml.jackson.annotation.JsonFormat.Shape.STRING) Instant checkedAt) {
        public Readiness {
            artifactDigest = ManifestChecks.hash(artifactDigest, "artifactDigest");
            manifestDigest = ManifestChecks.hash(manifestDigest, "manifestDigest");
            policyDigest = ManifestChecks.hash(policyDigest, "policyDigest");
            Objects.requireNonNull(checkedAt, "checkedAt");
            if (!componentsReady || !dependenciesReady || !policyLoaded) throw new IllegalArgumentException("pre-activation readiness failed");
        }

        public String digest() {
            return CanonicalJson.digest(Map.of("artifactDigest", artifactDigest, "manifestDigest", manifestDigest,
                    "policyDigest", policyDigest, "componentsReady", componentsReady, "dependenciesReady", dependenciesReady,
                    "policyLoaded", policyLoaded, "checkedAt", checkedAt.toString()));
        }
    }
}
