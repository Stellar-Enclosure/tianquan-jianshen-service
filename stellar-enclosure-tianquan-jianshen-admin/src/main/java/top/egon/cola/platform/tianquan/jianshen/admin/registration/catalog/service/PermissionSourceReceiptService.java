package top.egon.cola.platform.tianquan.jianshen.admin.registration.catalog.service;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import top.egon.cola.platform.tianquan.jianshen.admin.audit.domain.dto.AuditCommandDTO;
import top.egon.cola.platform.tianquan.jianshen.admin.audit.service.AuditQueryService;
import top.egon.cola.platform.tianquan.jianshen.admin.registration.catalog.repository.PermissionCatalogScopeRepository;
import top.egon.cola.platform.tianquan.jianshen.admin.registration.catalog.repository.PermissionManifestRepository;
import top.egon.cola.platform.tianquan.jianshen.admin.shared.domain.DatabaseClock;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.CatalogScope;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.ManifestRegistrationRequest;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.SourceImportReceipt;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.SourceImportRequest;
import top.egon.cola.platform.tianquan.jianshen.core.rule.Rbac3RuleViolation;

import java.util.Map;
import java.util.Optional;
import top.egon.cola.component.outbox.store.OutboxStatus;
import top.egon.cola.platform.tianquan.jianshen.admin.registration.catalog.repository.PermissionSourceOutboxRepository;

/** Remote HTTP runs outside these transactions; only an exact immutable receipt advances READY. */
@Service
public class PermissionSourceReceiptService {

    private final PermissionCatalogScopeRepository scopes;
    private final PermissionManifestRepository manifests;
    private final AuditQueryService audit;
    private final DatabaseClock clock;
    private final PermissionSourceOutboxRepository outbox;

    public PermissionSourceReceiptService(PermissionCatalogScopeRepository scopes, PermissionManifestRepository manifests,
                                           AuditQueryService audit, DatabaseClock clock, PermissionSourceOutboxRepository outbox) {
        this.scopes = scopes;
        this.manifests = manifests;
        this.audit = audit;
        this.clock = clock;
        this.outbox = outbox;
    }

    public Optional<String> deadPayload(String messageId) {
        return outbox.find(messageId).filter(message -> message.getStatus() == OutboxStatus.DEAD)
                .map(message -> message.getPayload());
    }

    @Transactional
    public SourceImportRequest load(CatalogScope target, String producer, long revision, String operationId, String digest) {
        scopes.lockOwner(target, producer);
        SourceImportRequest source = manifests.sourceImport(target, producer, revision);
        if (!source.operationId().equals(operationId) || !source.digests().manifestDigest().equals(digest)) {
            throw new Rbac3RuleViolation("RESOURCE_MANIFEST_CONFLICT");
        }
        return source;
    }

    @Transactional(readOnly = true)
    public boolean ready(SourceImportRequest source) {
        var receipt = manifests.sourceReceipt(source.scope(), source.producerId(), Long.parseLong(source.producerVersion()));
        if (receipt.isEmpty()) return false;
        if (!receipt.get().matches(source)) throw new Rbac3RuleViolation("RESOURCE_MANIFEST_CONFLICT");
        return manifests.findVersion(source.scope(), source.producerId(), Long.parseLong(source.producerVersion()))
                .map(manifest -> manifest.state().equals("READY")).orElse(false);
    }

    @Transactional
    public void accept(SourceImportRequest source, SourceImportReceipt receipt) {
        scopes.lockOwner(source.scope(), source.producerId());
        SourceImportRequest stored = manifests.sourceImport(source.scope(), source.producerId(), Long.parseLong(source.producerVersion()));
        if (!stored.requestDigest().equals(source.requestDigest()) || !receipt.matches(stored)) {
            throw new Rbac3RuleViolation("RESOURCE_MANIFEST_CONFLICT");
        }
        var previous = manifests.sourceReceipt(source.scope(), source.producerId(), Long.parseLong(source.producerVersion()));
        if (previous.isPresent()) {
            if (!previous.get().equals(receipt)) throw new Rbac3RuleViolation("IDEMPOTENCY_CONFLICT");
            if (!ready(source)) throw new Rbac3RuleViolation("AUTH_RUNTIME_UNAVAILABLE");
            return;
        }
        var now = clock.transactionNow();
        manifests.resumeMetadata(source, now);
        manifests.saveSourceReceipt(receipt, now);
        manifests.markReady(receipt, now);
        audit.record(new AuditCommandDTO(source.scope().tenantId(), "PERMISSION_METADATA_READY", "SUCCESS", "INFO", "SYSTEM",
                "permission-source-publisher", "CATALOG_SCOPE", source.scope().catalogScopeId(), null, "ALLOW", source.operationId(), source.operationId(), Map.of(),
                Map.of("scope", ManifestRegistrationRequest.targetMap(source.scope()), "producerId", source.producerId(),
                        "producerVersion", source.producerVersion(), "manifestDigest", source.digests().manifestDigest(), "receiptId", receipt.receiptId()), now));
    }

    @Transactional
    public void fail(SourceImportRequest source, long metadataRevision, String code) {
        if (code == null || !code.matches("[A-Z0-9_]{1,128}")) throw new IllegalArgumentException("invalid metadata failure code");
        scopes.lockOwner(source.scope(), source.producerId());
        manifests.markFailed(source, metadataRevision, code, clock.transactionNow());
    }
}
