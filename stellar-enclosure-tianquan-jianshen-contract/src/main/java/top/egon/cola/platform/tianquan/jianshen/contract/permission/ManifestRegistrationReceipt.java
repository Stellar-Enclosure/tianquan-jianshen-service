package top.egon.cola.platform.tianquan.jianshen.contract.permission;

import java.time.Instant;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;

/** Immutable original registration outcome; current metadata readiness is returned separately. */
public record ManifestRegistrationReceipt(
        String operationId,
        String planId,
        CatalogScope scope,
        String producerId,
        String producerVersion,
        ManifestDigests digests,
        Map<String, String> resourceIds,
        Map<String, String> permissionIds,
        int resourceCount,
        int permissionCount,
        int messageCount,
        Instant registeredAt
) {

    public ManifestRegistrationReceipt {
        if (operationId == null || !UUID.fromString(operationId).toString().equals(operationId)) {
            throw new IllegalArgumentException("operationId must be a canonical UUID");
        }
        planId = ManifestChecks.decimal(planId, "planId", false);
        Objects.requireNonNull(scope, "scope");
        producerId = ManifestChecks.identifier(producerId, "producerId", 128);
        producerVersion = ManifestChecks.decimal(producerVersion, "producerVersion", false);
        Objects.requireNonNull(digests, "digests");
        resourceIds = SourceImportRequest.immutableIds(resourceIds, "resourceIds", 200);
        permissionIds = SourceImportRequest.immutableIds(permissionIds, "permissionIds", 128);
        if (resourceCount != resourceIds.size() || permissionCount != permissionIds.size() || messageCount < 0 || messageCount > 20_000) {
            throw new IllegalArgumentException("registration receipt counts differ from content");
        }
        Objects.requireNonNull(registeredAt, "registeredAt");
    }
}
