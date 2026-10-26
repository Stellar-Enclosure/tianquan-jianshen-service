package top.egon.cola.platform.tianquan.jianshen.contract.permission;

import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

public record SourceImportReceipt(
        String receiptId,
        String operationId,
        CatalogScope scope,
        String producerId,
        String producerVersion,
        String sourceVersion,
        ManifestDigests digests,
        String projectionDigest,
        int resourceCount,
        int permissionCount,
        int messageCount,
        Instant importedAt
) {

    public SourceImportReceipt {
        receiptId = ManifestChecks.decimal(receiptId, "receiptId", false);
        if (operationId == null || !UUID.fromString(operationId).toString().equals(operationId)) {
            throw new IllegalArgumentException("operationId must be a canonical UUID");
        }
        Objects.requireNonNull(scope, "scope");
        producerId = ManifestChecks.identifier(producerId, "producerId", 128);
        producerVersion = ManifestChecks.decimal(producerVersion, "producerVersion", false);
        sourceVersion = ManifestChecks.hash(sourceVersion, "sourceVersion");
        Objects.requireNonNull(digests, "digests");
        if (!sourceVersion.equals(digests.manifestDigest()) || resourceCount < 0 || resourceCount > 10_000
                || permissionCount < 0 || permissionCount > 10_000 || messageCount < 0 || messageCount > 20_000) {
            throw new IllegalArgumentException("source receipt content is inconsistent");
        }
        projectionDigest = ManifestChecks.hash(projectionDigest, "projectionDigest");
        Objects.requireNonNull(importedAt, "importedAt");
    }

    public boolean matches(SourceImportRequest request) {
        return operationId.equals(request.operationId()) && scope.equals(request.scope())
                && producerId.equals(request.producerId()) && producerVersion.equals(request.producerVersion())
                && sourceVersion.equals(request.sourceVersion()) && digests.equals(request.digests())
                && projectionDigest.equals(request.projectionDigest())
                && resourceCount == request.resourceIds().size() && permissionCount == request.permissionIds().size()
                && messageCount == request.manifest().messages().size();
    }
}
