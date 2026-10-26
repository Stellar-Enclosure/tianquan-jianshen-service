package top.egon.cola.platform.tianquan.jianshen.contract;

import org.junit.jupiter.api.Test;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.ActivationDescriptor;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.CatalogScope;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.ManifestDigests;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.PermissionManifestCanonicalizer;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.PermissionManifestReader;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.SourceImportReceipt;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.SourceImportRequest;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PermissionSourceContractTest {

    @Test
    void sameSourceRequiresExactTargetVersionIdsAndMatchedReceipt() throws Exception {
        var manifest = new PermissionManifestReader().read(PermissionCanonicalizationTest.fixture());
        var digests = new PermissionManifestCanonicalizer().digests(manifest);
        var scope = new CatalogScope("101", "201", "trade", "order", "default", "test");
        String operation = UUID.randomUUID().toString();
        var request = new SourceImportRequest(operation, scope, "order-api", "1", digests.manifestDigest(),
                manifest, digests, Map.of("order.api.detail", "301", "order.field.amount", "302"),
                Map.of("order:read", "401", "order:amount:write", "402"));
        var receipt = new SourceImportReceipt("501", operation, scope, "order-api", "1", digests.manifestDigest(),
                digests, request.projectionDigest(), 2, 2, 4, Instant.parse("2026-10-23T00:00:00Z"));
        assertTrue(receipt.matches(request));
        var wrongProjection = new SourceImportReceipt("501", operation, scope, "order-api", "1", digests.manifestDigest(),
                digests, "0".repeat(64), 2, 2, 4, receipt.importedAt());
        assertFalse(wrongProjection.matches(request));
        assertThrows(IllegalArgumentException.class, () -> new SourceImportRequest(operation,
                new CatalogScope("102", "201", "other", "order", "default", "test"),
                "order-api", "1", digests.manifestDigest(), manifest, digests, request.resourceIds(), request.permissionIds()));
        assertThrows(IllegalArgumentException.class, () -> new SourceImportRequest(operation, scope,
                "order-api", "1", digests.manifestDigest(), manifest, digests, Map.of(), request.permissionIds()));
    }

    @Test
    void deploymentSelectionUsesTheExactProducerEntryAndStringLongIds() {
        var scope = new CatalogScope("9223372036854775807", "201", "trade", "order", "default", "test");
        var digests = new ManifestDigests("a".repeat(64), "b".repeat(64), "c".repeat(64));
        var producer = new ActivationDescriptor.ProducerVersion("order-api", "1", digests.manifestDigest(),
                digests, "601", "d".repeat(64));
        var descriptor = new ActivationDescriptor(scope, "3", UUID.randomUUID().toString(), "7",
                Instant.parse("2026-10-23T00:00:00Z"), List.of(producer));
        assertEquals(producer, descriptor.requireProducer("order-api", "1"));
        assertThrows(IllegalArgumentException.class, () -> descriptor.requireProducer("order-api", "2"));
        assertThrows(IllegalArgumentException.class, () -> new CatalogScope("9223372036854775808", "201",
                "trade", "order", "default", "test"));
        assertThrows(IllegalArgumentException.class, () -> new CatalogScope("01", "201", "trade", "order", "default", "test"));
    }
}
