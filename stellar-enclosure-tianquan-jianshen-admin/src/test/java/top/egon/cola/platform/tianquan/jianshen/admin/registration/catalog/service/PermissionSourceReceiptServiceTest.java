package top.egon.cola.platform.tianquan.jianshen.admin.registration.catalog.service;

import top.egon.cola.platform.tianquan.jianshen.admin.registration.catalog.repository.PermissionSourceOutboxRepository;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import top.egon.cola.platform.tianquan.jianshen.admin.audit.service.AuditQueryService;
import top.egon.cola.platform.tianquan.jianshen.admin.registration.catalog.repository.PermissionCatalogScopeRepository;
import top.egon.cola.platform.tianquan.jianshen.admin.registration.catalog.repository.PermissionManifestRepository;
import top.egon.cola.platform.tianquan.jianshen.admin.shared.domain.DatabaseClock;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.PermissionManifestCanonicalizer;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.SourceImportReceipt;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.SourceImportRequest;
import top.egon.cola.platform.tianquan.jianshen.core.rule.Rbac3RuleViolation;

import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class PermissionSourceReceiptServiceTest {

    private final PermissionCatalogScopeRepository scopes = mock(PermissionCatalogScopeRepository.class);
    private final PermissionManifestRepository manifests = mock(PermissionManifestRepository.class);
    private final AuditQueryService audit = mock(AuditQueryService.class);
    private final DatabaseClock clock = mock(DatabaseClock.class);
    private final PermissionSourceReceiptService service = new PermissionSourceReceiptService(scopes, manifests, audit, clock, mock(PermissionSourceOutboxRepository.class));
    private SourceImportRequest source;
    private SourceImportReceipt receipt;

    @BeforeEach
    void prepare() {
        var manifest = PermissionCatalogFixture.manifest();
        var digests = new PermissionManifestCanonicalizer().digests(manifest);
        source = new SourceImportRequest(PermissionCatalogFixture.OPERATION, PermissionCatalogFixture.SCOPE, "api", "1", digests.manifestDigest(),
                manifest, digests, Map.of("app.read", "101"), Map.of("app.read", "201"));
        receipt = new SourceImportReceipt("300", source.operationId(), source.scope(), source.producerId(), source.producerVersion(),
                source.sourceVersion(), source.digests(), source.projectionDigest(), 1, 1, 1, PermissionCatalogFixture.NOW);
        when(clock.transactionNow()).thenReturn(PermissionCatalogFixture.NOW);
        when(manifests.sourceImport(source.scope(), "api", 1)).thenReturn(source);
        when(manifests.sourceReceipt(source.scope(), "api", 1)).thenReturn(Optional.empty());
    }

    @Test
    void exactReceiptIsSavedBeforeAdvancingReady() {
        service.accept(source, receipt);
        var sequence = inOrder(manifests, audit);
        sequence.verify(manifests).sourceImport(source.scope(), "api", 1);
        sequence.verify(manifests).sourceReceipt(source.scope(), "api", 1);
        sequence.verify(manifests).resumeMetadata(source, PermissionCatalogFixture.NOW);
        sequence.verify(manifests).saveSourceReceipt(receipt, PermissionCatalogFixture.NOW);
        sequence.verify(manifests).markReady(receipt, PermissionCatalogFixture.NOW);
        sequence.verify(audit).record(any());
    }

    @Test
    void mismatchedProjectionOrCountsNeverAdvanceReady() {
        var invalid = new SourceImportReceipt(receipt.receiptId(), receipt.operationId(), receipt.scope(), receipt.producerId(), receipt.producerVersion(),
                receipt.sourceVersion(), receipt.digests(), "a".repeat(64), 1, 1, 1, receipt.importedAt());
        assertThrows(Rbac3RuleViolation.class, () -> service.accept(source, invalid));
        verify(manifests, never()).saveSourceReceipt(any(), any());
        verify(manifests, never()).markReady(any(), any());
    }

    @Test
    void exactReadyRetryDoesNotRewriteImmutableReceiptOrTerminalManifest() {
        when(manifests.sourceReceipt(source.scope(), "api", 1)).thenReturn(Optional.of(receipt));
        when(manifests.findVersion(source.scope(), "api", 1)).thenReturn(Optional.of(new PermissionManifestRepository.StoredManifest(
                1, source.manifest(), source.digests(), source.operationId(), "READY", null, 2)));
        service.accept(source, receipt);
        verify(manifests, never()).saveSourceReceipt(any(), any());
        verify(manifests, never()).markReady(any(), any());
        verify(manifests, never()).resumeMetadata(any(), any());
    }

    @Test
    void sameOperationWithDifferentRemoteReceiptIdIsRejected() {
        when(manifests.sourceReceipt(source.scope(), "api", 1)).thenReturn(Optional.of(receipt));
        var different = new SourceImportReceipt("301", receipt.operationId(), receipt.scope(), receipt.producerId(), receipt.producerVersion(),
                receipt.sourceVersion(), receipt.digests(), receipt.projectionDigest(), 1, 1, 1, receipt.importedAt());
        assertEquals("IDEMPOTENCY_CONFLICT", assertThrows(Rbac3RuleViolation.class, () -> service.accept(source, different)).reasonCode());
    }

    @Test
    void outboxPointerMustMatchStoredOperationAndDigest() {
        assertThrows(Rbac3RuleViolation.class, () -> service.load(source.scope(), "api", 1,
                "00000000-0000-0000-0000-000000000002", source.sourceVersion()));
        assertThrows(Rbac3RuleViolation.class, () -> service.load(source.scope(), "api", 1, source.operationId(), "f".repeat(64)));
        verify(manifests, never()).markFailed(any(), anyLong(), anyString(), any());
    }
}
