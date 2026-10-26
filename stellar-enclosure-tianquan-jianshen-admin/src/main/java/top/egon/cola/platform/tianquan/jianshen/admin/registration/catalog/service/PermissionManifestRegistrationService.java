package top.egon.cola.platform.tianquan.jianshen.admin.registration.catalog.service;

import top.egon.cola.platform.tianquan.jianshen.contract.permission.annotation.PermissionResource;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.ResourceAccess;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.ResourceType;

import top.egon.cola.platform.tianquan.jianshen.admin.registration.catalog.domain.PermissionSourceEventIdentity;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import top.egon.cola.platform.tianquan.jianshen.admin.audit.domain.dto.AuditCommandDTO;
import top.egon.cola.platform.tianquan.jianshen.admin.audit.service.AuditQueryService;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.runtime.domain.vo.AuthorizationEventVO;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.runtime.repository.AuthorizationEventPublisher;
import top.egon.cola.platform.tianquan.jianshen.admin.registration.catalog.domain.PermissionCatalogCaller;
import top.egon.cola.platform.tianquan.jianshen.admin.registration.catalog.domain.PermissionRegistrationPlan;
import top.egon.cola.platform.tianquan.jianshen.admin.registration.catalog.repository.PermissionCatalogDefinitionRepository;
import top.egon.cola.platform.tianquan.jianshen.admin.registration.catalog.repository.PermissionCatalogScopeRepository;
import top.egon.cola.platform.tianquan.jianshen.admin.registration.catalog.repository.PermissionManifestRepository;
import top.egon.cola.platform.tianquan.jianshen.admin.registration.catalog.repository.PermissionSourceOutboxRepository;
import top.egon.cola.platform.tianquan.jianshen.admin.shared.domain.DatabaseClock;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.CatalogScope;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.ManifestRegistrationReceipt;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.ManifestRegistrationRequest;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.PermissionManifest;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.SourceImportRequest;
import top.egon.cola.platform.tianquan.jianshen.core.rule.Rbac3RuleViolation;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;

/** One local transaction creates candidate definitions, the original receipt, audit and Outbox. */
@Service
public class PermissionManifestRegistrationService {

    public record Result(@PermissionResource(key = "tianquan-jianshen.field.registration.catalog.service.PermissionManifestRegistrationService.Result.receipt", type = ResourceType.FIELD,
                labelPage = "tianquan-jianshen.permissions", labelKey = "field.receipt", access = ResourceAccess.PUBLIC,
                allowedPrincipals = {PermissionManifest.PrincipalType.SERVICE}, oauthScopes = {"tianquan-jianshen:permission-manifest:register"})
        ManifestRegistrationReceipt receipt, @PermissionResource(key = "tianquan-jianshen.field.registration.catalog.service.PermissionManifestRegistrationService.Result.currentState", type = ResourceType.FIELD,
                labelPage = "tianquan-jianshen.permissions", labelKey = "field.currentState", access = ResourceAccess.PUBLIC,
                allowedPrincipals = {PermissionManifest.PrincipalType.SERVICE}, oauthScopes = {"tianquan-jianshen:permission-manifest:register"})
        String currentState, @PermissionResource(key = "tianquan-jianshen.field.registration.catalog.service.PermissionManifestRegistrationService.Result.failureCode", type = ResourceType.FIELD,
                labelPage = "tianquan-jianshen.permissions", labelKey = "field.failureCode", access = ResourceAccess.PUBLIC,
                allowedPrincipals = {PermissionManifest.PrincipalType.SERVICE}, oauthScopes = {"tianquan-jianshen:permission-manifest:register"})
        String failureCode) { }

    private final PermissionCatalogScopeRepository scopes;
    private final PermissionCatalogDefinitionRepository definitions;
    private final PermissionManifestRepository manifests;
    private final AuthorizationEventPublisher outbox;
    private final AuditQueryService audit;
    private final DatabaseClock clock;
    private final PermissionSourceOutboxRepository sourceOutbox;

    public PermissionManifestRegistrationService(PermissionCatalogScopeRepository scopes, PermissionCatalogDefinitionRepository definitions,
                                                 PermissionManifestRepository manifests, AuthorizationEventPublisher outbox,
                                                 AuditQueryService audit, DatabaseClock clock, PermissionSourceOutboxRepository sourceOutbox) {
        this.scopes = scopes;
        this.definitions = definitions;
        this.manifests = manifests;
        this.outbox = outbox;
        this.audit = audit;
        this.clock = clock;
        this.sourceOutbox = sourceOutbox;
    }

    @Transactional
    public Result register(ManifestRegistrationRequest.Apply request, PermissionCatalogCaller caller) {
        Instant now = clock.transactionNow();
        var authorized = scopes.authorize(request.target(), request.producerId(), caller, PermissionCatalogCaller.Capability.REGISTER, now);
        var existing = manifests.findOperation(request.target(), request.producerId(), request.operationId());
        if (existing.isPresent()) {
            if (!existing.get().requestDigest().equals(request.requestDigest())) throw new Rbac3RuleViolation("IDEMPOTENCY_CONFLICT");
            return current(existing.get().receipt());
        }
        var owner = authorized.owner();
        PermissionManifestPlanService.requireVersions(request.expectedProducerRevision(), request.expectedActiveRevision(), owner);
        PermissionRegistrationPlan plan = manifests.findPlan(request.target(), request.producerId(), Long.parseLong(request.planId()))
                .orElseThrow(() -> new Rbac3RuleViolation("RESOURCE_NOT_FOUND"));
        if (!now.isBefore(plan.expiresAt()) || plan.ownerVersion() != owner.ownerVersion()
                || plan.serviceGrantId() != authorized.grant().id() || plan.serviceGrantVersion() != authorized.grant().version()
                || !plan.digests().equals(request.digests())
                || !plan.request().expectedProducerRevision().equals(request.expectedProducerRevision())
                || !plan.request().expectedActiveRevision().equals(request.expectedActiveRevision())) {
            throw new Rbac3RuleViolation("RESOURCE_VERSION_CONFLICT");
        }
        PermissionManifest manifest = plan.request().manifest();
        if (manifest.producer().snapshotMode() != PermissionManifest.SnapshotMode.FULL || plan.diff().conflicts()) {
            throw new Rbac3RuleViolation("RESOURCE_MANIFEST_INVALID");
        }
        if (manifest.producer().clearIntent()) {
            caller.require(request.target(), PermissionCatalogCaller.Capability.CLEAR_PRODUCER, now);
            authorized.grant().require(PermissionCatalogCaller.Capability.CLEAR_PRODUCER);
        }
        var identities = definitions.load(request.target());
        definitions.validate(owner, manifest, identities);
        String actor = "service:" + caller.bindingDigest();
        var sameContent = manifests.findByDigest(request.target(), request.producerId(), request.digests().manifestDigest());
        SourceImportRequest source;
        if (sameContent.isPresent()) {
            // Reuse stable IDs and the original source operation; do not rewind the producer head.
            var previous = sameContent.get();
            source = manifests.sourceImport(request.target(), request.producerId(), previous.producerVersion());
            boolean exhausted = previous.state().equals("METADATA_PENDING") && sourceOutbox.dead(
                    request.target(), request.producerId(), previous.producerVersion(), previous.metadataRevision());
            if (previous.state().equals("FAILED") || exhausted) {
                long failedVersion = previous.metadataRevision();
                if (exhausted) {
                    if (!manifests.markFailed(source, failedVersion, "METADATA_DELIVERY_EXHAUSTED", now)) {
                        throw new Rbac3RuleViolation("RESOURCE_VERSION_CONFLICT");
                    }
                    failedVersion = Math.addExact(failedVersion, 1);
                }
                enqueueSource(source, manifests.restartMetadata(source, failedVersion, now));
            }
        } else {
            long revision = scopes.advanceProducer(owner, actor, now);
            var ids = definitions.assign(owner, manifest, identities, actor, now);
            manifests.saveManifest(request.target(), manifest, request.digests(), revision, request.operationId(), plan.diff(), actor, now);
            definitions.saveVersions(request.target(), manifest, revision, ids, identities);
            manifests.seal(request.target(), request.producerId(), revision, now);
            source = new SourceImportRequest(request.operationId(), request.target(), request.producerId(), Long.toString(revision),
                    request.digests().manifestDigest(), manifest, request.digests(), ids.resources(), ids.permissions());
            enqueueSource(source, 1);
        }
        ManifestRegistrationReceipt receipt = new ManifestRegistrationReceipt(request.operationId(), request.planId(), request.target(),
                request.producerId(), source.producerVersion(), source.digests(), source.resourceIds(), source.permissionIds(),
                source.resourceIds().size(), source.permissionIds().size(), source.manifest().messages().size(), now);
        manifests.saveOperation(request, receipt);
        audit.record(new AuditCommandDTO(request.target().tenantId(), "PERMISSION_MANIFEST_REGISTERED", "SUCCESS", "INFO", "SERVICE",
                actor, "CATALOG_SCOPE", request.target().catalogScopeId(), null, "ALLOW", request.operationId(), request.operationId(), Map.of(),
                Map.of("scope", ManifestRegistrationRequest.targetMap(request.target()), "producerId", request.producerId(),
                        "producerVersion", source.producerVersion(), "manifestDigest", source.digests().manifestDigest(),
                        "resourceCount", receipt.resourceCount(), "permissionCount", receipt.permissionCount()), now));
        return current(receipt);
    }

    @Transactional
    public Result status(CatalogScope target, String producer, String operationId, PermissionCatalogCaller caller) {
        if (!UUID.fromString(operationId).toString().equals(operationId)) throw new IllegalArgumentException("invalid operationId");
        scopes.authorize(target, producer, caller, PermissionCatalogCaller.Capability.REGISTER, clock.transactionNow());
        return current(manifests.findOperation(target, producer, operationId)
                .orElseThrow(() -> new Rbac3RuleViolation("RESOURCE_NOT_FOUND")).receipt());
    }

    private Result current(ManifestRegistrationReceipt receipt) {
        var manifest = manifests.findVersion(receipt.scope(), receipt.producerId(), Long.parseLong(receipt.producerVersion()))
                .orElseThrow(() -> new Rbac3RuleViolation("AUTH_RUNTIME_UNAVAILABLE"));
        if (manifest.state().equals("METADATA_PENDING") && sourceOutbox.dead(receipt.scope(), receipt.producerId(), Long.parseLong(receipt.producerVersion()), manifest.metadataRevision())) {
            return new Result(receipt, "FAILED", "METADATA_DELIVERY_EXHAUSTED");
        }
        return new Result(receipt, manifest.state(), manifest.failureCode());
    }

    private void enqueueSource(SourceImportRequest source, long metadataRevision) {
        String aggregateId = PermissionSourceEventIdentity.permissionSourceAggregateId(
                source.scope().catalogScopeId(), source.producerId(), Long.parseLong(source.producerVersion()));
        outbox.enqueue(new AuthorizationEventVO(source.scope().tenantId(), "PERMISSION_PRODUCER", aggregateId,
                "PERMISSION_SOURCE_IMPORT_REQUESTED", sourceEvent(source, metadataRevision), source.operationId()));
    }

    private Map<String, String> sourceEvent(SourceImportRequest source, long metadataRevision) {
        Map<String, String> result = new LinkedHashMap<>();
        ManifestRegistrationRequest.targetMap(source.scope()).forEach((key, value) -> result.put(key, value.toString()));
        result.put("producerId", source.producerId());
        result.put("producerVersion", source.producerVersion());
        result.put("aggregateVersion", Long.toString(metadataRevision));
        result.put("operationId", source.operationId());
        result.put("manifestDigest", source.digests().manifestDigest());
        return Map.copyOf(result);
    }
}
