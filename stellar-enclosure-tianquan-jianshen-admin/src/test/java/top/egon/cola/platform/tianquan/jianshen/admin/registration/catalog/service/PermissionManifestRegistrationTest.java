package top.egon.cola.platform.tianquan.jianshen.admin.registration.catalog.service;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import top.egon.cola.platform.tianquan.jianshen.admin.audit.service.AuditQueryService;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.runtime.domain.vo.AuthorizationEventVO;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.runtime.repository.AuthorizationEventPublisher;
import top.egon.cola.platform.tianquan.jianshen.admin.registration.catalog.domain.PermissionRegistrationPlan;
import top.egon.cola.platform.tianquan.jianshen.admin.registration.catalog.repository.PermissionCatalogDefinitionRepository;
import top.egon.cola.platform.tianquan.jianshen.admin.registration.catalog.repository.PermissionCatalogScopeRepository;
import top.egon.cola.platform.tianquan.jianshen.admin.registration.catalog.repository.PermissionManifestRepository;
import top.egon.cola.platform.tianquan.jianshen.admin.registration.catalog.repository.PermissionSourceOutboxRepository;
import top.egon.cola.platform.tianquan.jianshen.admin.shared.domain.DatabaseClock;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.ManifestRegistrationReceipt;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.ManifestRegistrationRequest;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.PermissionManifestCanonicalizer;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.SourceImportRequest;
import top.egon.cola.platform.tianquan.jianshen.core.registration.PermissionManifestDiff;
import top.egon.cola.platform.tianquan.jianshen.core.rule.Rbac3RuleViolation;

import java.util.Map;
import java.util.Optional;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static top.egon.cola.platform.tianquan.jianshen.admin.registration.catalog.service.PermissionCatalogFixture.NOW;
import static top.egon.cola.platform.tianquan.jianshen.admin.registration.catalog.service.PermissionCatalogFixture.OPERATION;
import static top.egon.cola.platform.tianquan.jianshen.admin.registration.catalog.service.PermissionCatalogFixture.SCOPE;

class PermissionManifestRegistrationTest {

    private final PermissionCatalogScopeRepository scopes = mock(PermissionCatalogScopeRepository.class);
    private final PermissionCatalogDefinitionRepository definitions = mock(PermissionCatalogDefinitionRepository.class);
    private final PermissionManifestRepository manifests = mock(PermissionManifestRepository.class);
    private final AuthorizationEventPublisher outbox = mock(AuthorizationEventPublisher.class);
    private final AuditQueryService audit = mock(AuditQueryService.class);
    private final DatabaseClock clock = mock(DatabaseClock.class);
    private final PermissionSourceOutboxRepository sourceOutbox = mock(PermissionSourceOutboxRepository.class);
    private final PermissionManifestRegistrationService service = new PermissionManifestRegistrationService(scopes, definitions, manifests, outbox, audit, clock, sourceOutbox);
    private ManifestRegistrationRequest.Apply request;
    private PermissionRegistrationPlan plan;

    @BeforeEach
    void prepare() {
        prepareRevision(0);
    }

    private void prepareRevision(long revision) {
        var manifest = PermissionCatalogFixture.manifest();
        var digests = new PermissionManifestCanonicalizer().digests(manifest);
        request = new ManifestRegistrationRequest.Apply(SCOPE, "api", "100", OPERATION, digests, Long.toString(revision), "0");
        plan = new PermissionRegistrationPlan(100, new ManifestRegistrationRequest.Plan(SCOPE, manifest, Long.toString(revision), "0"),
                5, 30, 2, digests, new PermissionManifestDiff().compare(null, manifest, Set.of()), NOW.plusSeconds(300), NOW, "service");
        when(clock.transactionNow()).thenReturn(NOW);
        when(scopes.authorize(any(), anyString(), any(), any(), any())).thenReturn(
                new PermissionCatalogScopeRepository.AuthorizedOwner(PermissionCatalogFixture.owner(revision), PermissionCatalogFixture.grant()));
        when(scopes.advanceProducer(any(), anyString(), any())).thenReturn(revision + 1);
        when(definitions.load(SCOPE)).thenReturn(new PermissionCatalogDefinitionRepository.Identities(Map.of(), Map.of(), Map.of()));
        when(definitions.assign(any(), any(), any(), anyString(), any())).thenReturn(
                new PermissionCatalogDefinitionRepository.AssignedIds(Map.of("app.read", "101"), Map.of("app.read", "201")));
        when(manifests.findOperation(SCOPE, "api", OPERATION)).thenReturn(Optional.empty());
        when(manifests.findPlan(SCOPE, "api", 100)).thenReturn(Optional.of(plan));
        when(manifests.findByDigest(SCOPE, "api", digests.manifestDigest())).thenReturn(Optional.empty());
        when(manifests.findVersion(eq(SCOPE), eq("api"), anyLong())).thenAnswer(invocation -> Optional.of(
                new PermissionManifestRepository.StoredManifest(invocation.getArgument(2), manifest, digests, OPERATION, "METADATA_PENDING", null, 1)));
    }

    @Test
    void persistsCandidateAndOriginalReceiptAndBoundedOutboxWithoutActivating() {
        var result = service.register(request, PermissionCatalogFixture.caller());
        assertEquals("METADATA_PENDING", result.currentState());
        assertEquals("1", result.receipt().producerVersion());
        assertEquals(Map.of("app.read", "101"), result.receipt().resourceIds());
        assertEquals(Map.of("app.read", "201"), result.receipt().permissionIds());
        verify(manifests).saveOperation(request, result.receipt());
        verify(manifests).seal(SCOPE, "api", 1, NOW);
        ArgumentCaptor<AuthorizationEventVO> event = ArgumentCaptor.forClass(AuthorizationEventVO.class);
        verify(outbox).enqueue(event.capture());
        assertEquals("PERMISSION_SOURCE_IMPORT_REQUESTED", event.getValue().eventType());
        assertEquals("1", event.getValue().safePayload().get("catalogScopeId"));
        assertEquals(OPERATION, event.getValue().safePayload().get("operationId"));
        assertFalse(event.getValue().safePayload().containsKey("manifest"));
    }

    @Test
    void exactOperationReplayReturnsOriginalIdsEvenAfterPlanExpiryAndHeadAdvance() {
        var receipt = receipt();
        prepareRevision(2);
        var original = new ManifestRegistrationRequest.Apply(SCOPE, "api", "100", OPERATION, receipt.digests(), "0", "0");
        when(clock.transactionNow()).thenReturn(NOW.plusSeconds(600));
        when(manifests.findOperation(SCOPE, "api", OPERATION)).thenReturn(Optional.of(
                new PermissionManifestRepository.StoredOperation(original.requestDigest(), receipt)));
        assertEquals(receipt, service.register(original, PermissionCatalogFixture.caller()).receipt());
        verify(manifests, never()).findPlan(any(), anyString(), anyLong());
        verify(scopes, never()).advanceProducer(any(), anyString(), any());
        verify(outbox, never()).enqueue(any());
    }

    @Test
    void sameOperationWithDifferentPlanIsConflict() {
        when(manifests.findOperation(SCOPE, "api", OPERATION)).thenReturn(Optional.of(
                new PermissionManifestRepository.StoredOperation("a".repeat(64), receipt())));
        assertEquals("IDEMPOTENCY_CONFLICT", assertThrows(Rbac3RuleViolation.class,
                () -> service.register(request, PermissionCatalogFixture.caller())).reasonCode());
        verify(definitions, never()).assign(any(), any(), any(), anyString(), any());
    }

    @Test
    void terminalOutboxFailureIsReportedEvenIfNotificationCouldNotUpdateManifest() {
        when(manifests.findOperation(SCOPE, "api", OPERATION)).thenReturn(Optional.of(
                new PermissionManifestRepository.StoredOperation(request.requestDigest(), receipt())));
        when(sourceOutbox.dead(SCOPE, "api", 1, 1)).thenReturn(true);
        var result = service.status(SCOPE, "api", OPERATION, PermissionCatalogFixture.caller());
        assertEquals("FAILED", result.currentState());
        assertEquals("METADATA_DELIVERY_EXHAUSTED", result.failureCode());
    }

    @Test
    void stalePlanOrGrantVersionCannotWrite() {
        when(clock.transactionNow()).thenReturn(NOW.plusSeconds(301));
        assertEquals("RESOURCE_VERSION_CONFLICT", assertThrows(Rbac3RuleViolation.class,
                () -> service.register(request, PermissionCatalogFixture.caller())).reasonCode());
        when(clock.transactionNow()).thenReturn(NOW);
        when(scopes.authorize(any(), anyString(), any(), any(), any())).thenReturn(new PermissionCatalogScopeRepository.AuthorizedOwner(
                PermissionCatalogFixture.owner(0), new PermissionCatalogScopeRepository.Grant(30, 3, Set.of("REGISTER"), Set.of(), false)));
        assertThrows(Rbac3RuleViolation.class, () -> service.register(request, PermissionCatalogFixture.caller()));
        verify(definitions, never()).assign(any(), any(), any(), anyString(), any());
        verify(outbox, never()).enqueue(any());
    }

    @Test
    void secondPipelineMustReplanAfterProducerRevisionChanges() {
        var old = request;
        prepareRevision(1);
        assertEquals("RESOURCE_VERSION_CONFLICT", assertThrows(Rbac3RuleViolation.class,
                () -> service.register(old, PermissionCatalogFixture.caller())).reasonCode());
        verify(manifests, never()).saveOperation(any(), any());
    }

    @Test
    void identicalContentReusesRevisionWithoutRewindingHeadOrDuplicateImport() {
        prepareRevision(2);
        var old = new PermissionManifestRepository.StoredManifest(1, plan.request().manifest(), plan.digests(),
                "00000000-0000-0000-0000-000000000002", "READY", null, 2);
        when(manifests.findByDigest(SCOPE, "api", plan.digests().manifestDigest())).thenReturn(Optional.of(old));
        when(manifests.sourceImport(SCOPE, "api", 1)).thenReturn(new SourceImportRequest(old.sourceOperationId(), SCOPE, "api", "1",
                old.digests().manifestDigest(), old.manifest(), old.digests(), Map.of("app.read", "101"), Map.of("app.read", "201")));
        when(manifests.findVersion(SCOPE, "api", 1)).thenReturn(Optional.of(old));
        var result = service.register(request, PermissionCatalogFixture.caller());
        assertEquals("1", result.receipt().producerVersion());
        assertEquals(OPERATION, result.receipt().operationId());
        assertEquals("READY", result.currentState());
        verify(scopes, never()).advanceProducer(any(), anyString(), any());
        verify(outbox, never()).enqueue(any());
    }

    @Test
    void newRegistrationOperationRestartsFailedDeliveryWithoutChangingOriginalSourceOrHead() {
        assertRecovery("FAILED", 2, false);
    }

    @Test
    void newRegistrationOperationRecoversDeadOutboxWhenListenerCouldNotPersistFailure() {
        assertRecovery("METADATA_PENDING", 1, true);
    }

    private void assertRecovery(String state, long metadataRevision, boolean exhausted) {
        prepareRevision(2);
        String originalOperation = "00000000-0000-0000-0000-000000000002";
        var old = new PermissionManifestRepository.StoredManifest(1, plan.request().manifest(), plan.digests(),
                originalOperation, state, state.equals("FAILED") ? "METADATA_DELIVERY_EXHAUSTED" : null, metadataRevision);
        var source = new SourceImportRequest(originalOperation, SCOPE, "api", "1", old.digests().manifestDigest(),
                old.manifest(), old.digests(), Map.of("app.read", "101"), Map.of("app.read", "201"));
        when(manifests.findByDigest(SCOPE, "api", plan.digests().manifestDigest())).thenReturn(Optional.of(old));
        when(manifests.sourceImport(SCOPE, "api", 1)).thenReturn(source);
        when(sourceOutbox.dead(SCOPE, "api", 1, metadataRevision)).thenReturn(exhausted);
        when(manifests.markFailed(source, metadataRevision, "METADATA_DELIVERY_EXHAUSTED", NOW)).thenReturn(true);
        when(manifests.restartMetadata(source, 2, NOW)).thenReturn(3L);
        when(manifests.findVersion(SCOPE, "api", 1)).thenReturn(Optional.of(new PermissionManifestRepository.StoredManifest(
                1, old.manifest(), old.digests(), originalOperation, "METADATA_PENDING", null, 3)));
        var result = service.register(request, PermissionCatalogFixture.caller());
        assertEquals("METADATA_PENDING", result.currentState());
        assertEquals("1", result.receipt().producerVersion());
        verify(scopes, never()).advanceProducer(any(), anyString(), any());
        verify(manifests).restartMetadata(source, 2, NOW);
        ArgumentCaptor<AuthorizationEventVO> event = ArgumentCaptor.forClass(AuthorizationEventVO.class);
        verify(outbox).enqueue(event.capture());
        assertEquals(originalOperation, event.getValue().safePayload().get("operationId"));
        assertEquals("3", event.getValue().safePayload().get("aggregateVersion"));
        assertEquals("1", event.getValue().safePayload().get("producerVersion"));
    }

    @Test
    void partialPlanNeverCreatesCandidateOrRetiresDefinitions() {
        var previous = plan.request().manifest();
        var producer = previous.producer();
        var partial = new top.egon.cola.platform.tianquan.jianshen.contract.permission.PermissionManifest(previous.schemaVersion(),
                previous.application(), new top.egon.cola.platform.tianquan.jianshen.contract.permission.PermissionManifest.Producer(
                producer.id(), producer.kind(), top.egon.cola.platform.tianquan.jianshen.contract.permission.PermissionManifest.SnapshotMode.PARTIAL,
                producer.ownedKeyPrefixes(), producer.expectedModules(), producer.scannedModules(), false), previous.artifact(), previous.permissionDefinitions(),
                previous.permissionReferences(), previous.resources(), previous.resourceReferences(), previous.messages());
        var hashes = new PermissionManifestCanonicalizer().digests(partial);
        var partialRequest = new ManifestRegistrationRequest.Apply(SCOPE, "api", "100", OPERATION, hashes, "0", "0");
        when(manifests.findPlan(SCOPE, "api", 100)).thenReturn(Optional.of(new PermissionRegistrationPlan(100,
                new ManifestRegistrationRequest.Plan(SCOPE, partial, "0", "0"), 5, 30, 2, hashes,
                new PermissionManifestDiff().compare(previous, partial, Set.of()), NOW.plusSeconds(300), NOW, "service")));
        assertEquals("RESOURCE_MANIFEST_INVALID", assertThrows(Rbac3RuleViolation.class,
                () -> service.register(partialRequest, PermissionCatalogFixture.caller())).reasonCode());
        verify(manifests, never()).saveManifest(any(), any(), any(), anyLong(), anyString(), any(), anyString(), any());
    }

    @Test
    void planIsOnlyReviewEvidenceAndBindsOwnerAndGrantVersions() {
        when(manifests.activeManifest(SCOPE, "api")).thenReturn(Optional.empty());
        when(manifests.grantedCodes(SCOPE)).thenReturn(Set.of("app.read"));
        var plans = new PermissionManifestPlanService(scopes, definitions, manifests, audit, clock, () -> 100L);
        var result = plans.plan(plan.request(), PermissionCatalogFixture.caller());
        assertTrue(result.diff().authorizationExpansion());
        assertEquals(NOW.plusSeconds(300), result.expiresAt());
        ArgumentCaptor<PermissionRegistrationPlan> saved = ArgumentCaptor.forClass(PermissionRegistrationPlan.class);
        verify(manifests).savePlan(saved.capture());
        assertEquals(5, saved.getValue().ownerVersion());
        assertEquals(2, saved.getValue().serviceGrantVersion());
        verify(definitions, never()).assign(any(), any(), any(), anyString(), any());
        verify(outbox, never()).enqueue(any());
    }

    private ManifestRegistrationReceipt receipt() {
        return new ManifestRegistrationReceipt(OPERATION, "100", SCOPE, "api", "1", plan.digests(),
                Map.of("app.read", "101"), Map.of("app.read", "201"), 1, 1, 1, NOW);
    }
}
