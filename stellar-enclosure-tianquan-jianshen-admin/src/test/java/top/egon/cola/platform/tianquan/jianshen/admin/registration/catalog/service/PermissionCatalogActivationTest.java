package top.egon.cola.platform.tianquan.jianshen.admin.registration.catalog.service;

import top.egon.cola.platform.tianquan.jianshen.admin.registration.catalog.repository.CatalogAdministrationGuard;

import top.egon.cola.platform.tianquan.jianshen.admin.registration.catalog.domain.vo.DeploymentQualificationReceiptVO;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import top.egon.cola.platform.tianquan.jianshen.admin.audit.service.AuditQueryService;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.runtime.repository.AuthorizationEventPublisher;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.runtime.state.repository.TenantAuthorizationStateRepository;
import top.egon.cola.platform.tianquan.jianshen.admin.registration.catalog.domain.PermissionCatalogCaller;
import top.egon.cola.platform.tianquan.jianshen.admin.registration.catalog.repository.DeploymentQualificationRepository;
import top.egon.cola.platform.tianquan.jianshen.admin.registration.catalog.repository.PermissionCatalogActivationRepository;
import top.egon.cola.platform.tianquan.jianshen.admin.registration.catalog.repository.PermissionCatalogScopeRepository;
import top.egon.cola.platform.tianquan.jianshen.admin.registration.catalog.repository.PermissionManifestRepository;
import top.egon.cola.platform.tianquan.jianshen.admin.shared.domain.DatabaseClock;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.ActivationDescriptor;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.CatalogActivationRequest;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.DeploymentQualificationRequest;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.PermissionManifestCanonicalizer;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.SourceImportReceipt;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.SourceImportRequest;
import top.egon.cola.platform.tianquan.jianshen.core.rule.Rbac3RuleViolation;

import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;
import static top.egon.cola.platform.tianquan.jianshen.admin.registration.catalog.service.PermissionCatalogFixture.*;

class PermissionCatalogActivationTest {
    private final PermissionCatalogScopeRepository scopes = mock(PermissionCatalogScopeRepository.class);
    private final PermissionManifestRepository manifests = mock(PermissionManifestRepository.class);
    private final DeploymentQualificationRepository qualifications = mock(DeploymentQualificationRepository.class);
    private final PermissionCatalogActivationRepository activations = mock(PermissionCatalogActivationRepository.class);
    private final TenantAuthorizationStateRepository policy = mock(TenantAuthorizationStateRepository.class);
    private final AuthorizationEventPublisher events = mock(AuthorizationEventPublisher.class);
    private final AuditQueryService audit = mock(AuditQueryService.class);
    private final DatabaseClock clock = mock(DatabaseClock.class);
    private final CatalogAdministrationGuard administration = mock(CatalogAdministrationGuard.class);
    private final PermissionCatalogActivationService service = new PermissionCatalogActivationService(scopes, manifests, qualifications, activations, policy, events, audit, clock, administration);
    private final CatalogActivationRequest request = new CatalogActivationRequest(SCOPE, OPERATION, "0", List.of(new CatalogActivationRequest.Selection("api", "1", "301")));
    private SourceImportRequest source;
    private PermissionManifestRepository.StoredManifest candidate;
    private DeploymentQualificationReceiptVO proof;

    @BeforeEach
    void prepare() {
        when(clock.transactionNow()).thenReturn(NOW);
        when(scopes.authorize(any(), anyString(), any(), any(), any())).thenReturn(new PermissionCatalogScopeRepository.AuthorizedOwner(owner(1), grant()));
        var manifest = manifest();
        var digests = new PermissionManifestCanonicalizer().digests(manifest);
        source = new SourceImportRequest(OPERATION, SCOPE, "api", "1", digests.manifestDigest(), manifest, digests,
                Map.of("app.read", "101"), Map.of("app.read", "201"));
        candidate = new PermissionManifestRepository.StoredManifest(1, manifest, digests, OPERATION, "READY", null, 2);
        when(manifests.findVersion(SCOPE, "api", 1)).thenReturn(Optional.of(candidate));
        when(manifests.sourceImport(SCOPE, "api", 1)).thenReturn(source);
        when(manifests.sourceReceipt(SCOPE, "api", 1)).thenReturn(Optional.of(new SourceImportReceipt("300", OPERATION, SCOPE, "api", "1",
                digests.manifestDigest(), digests, source.projectionDigest(), 1, 1, 1, NOW.minusSeconds(10))));
        var readiness = new DeploymentQualificationRequest.Readiness("f".repeat(64), digests.manifestDigest(), digests.policyDigest(), true, true, true, NOW);
        var attestation = new DeploymentQualificationRequest(SCOPE, "api", "1", "f".repeat(64), digests.manifestDigest(), digests.policyDigest(),
                "pipeline", "build", "refs/heads/main", "a".repeat(40), "deployment", readiness);
        proof = new DeploymentQualificationReceiptVO("301", "d".repeat(64), attestation, caller().issuer().toString(), "pipeline",
                caller().principal().resourceUri().toString(), NOW, NOW.plusSeconds(60));
        when(qualifications.requireTrusted(SCOPE, "api", 1, 301, NOW)).thenReturn(proof);
        when(policy.increment(eq(10L), anyString())).thenReturn(1L);
    }

    @Test
    void verifiesEveryGateBeforePublishingPointerVersionOutboxAndAudit() {
        var result = service.activate(request, caller());
        assertEquals("1", result.activationVersion());
        assertEquals("1", result.policyVersion());
        assertEquals("301", result.producers().getFirst().qualificationId());
        var order = inOrder(scopes, activations, qualifications, policy, events, audit);
        order.verify(scopes).authorize(SCOPE, "api", caller(), PermissionCatalogCaller.Capability.ACTIVATE, NOW);
        order.verify(activations).operation(SCOPE, OPERATION);
        order.verify(activations).requireComplete(request);
        order.verify(qualifications).requireTrusted(SCOPE, "api", 1, 301, NOW);
        order.verify(activations).requireReferenceClosure(request);
        order.verify(policy).increment(eq(10L), anyString());
        order.verify(activations).save(eq(request), eq(result), anyString());
        order.verify(events).enqueue(any());
        order.verify(audit).record(any());
    }

    @Test
    void originalOperationReplayDoesNotRequireExpiredDeploymentProofOrAdvanceHead() {
        var original = new ActivationDescriptor(SCOPE, "1", OPERATION, "1", NOW, List.of(new ActivationDescriptor.ProducerVersion("api", "1",
                source.sourceVersion(), source.digests(), "301", "f".repeat(64))));
        when(activations.operation(SCOPE, OPERATION)).thenReturn(Optional.of(new PermissionCatalogActivationRepository.Operation(request.requestDigest(), original)));
        assertEquals(original, service.activate(request, caller()));
        verifyNoInteractions(qualifications, policy, events);
    }

    @Test
    void conflictingOperationAndStaleActiveRevisionCannotPublish() {
        when(activations.operation(SCOPE, OPERATION)).thenReturn(Optional.of(new PermissionCatalogActivationRepository.Operation("a".repeat(64), null)));
        assertReason("IDEMPOTENCY_CONFLICT");
        when(activations.operation(SCOPE, OPERATION)).thenReturn(Optional.empty());
        var owner = owner(1);
        when(scopes.authorize(any(), anyString(), any(), any(), any())).thenReturn(new PermissionCatalogScopeRepository.AuthorizedOwner(
                new PermissionCatalogScopeRepository.Owner(SCOPE, 20, "api", owner.kind(), owner.resourcePrefixes(), owner.permissionPrefixes(),
                        owner.messagePrefixes(), owner.expectedModules(), 1, 5, 1, 1), grant()));
        assertReason("RESOURCE_VERSION_CONFLICT");
        verifyNoInteractions(qualifications, policy, events);
    }

    @Test
    void incompleteProducerSetAndBrokenClosureCannotPublish() {
        doThrow(new Rbac3RuleViolation("RESOURCE_MANIFEST_CONFLICT")).when(activations).requireComplete(request);
        assertReason("RESOURCE_MANIFEST_CONFLICT");
        verifyNoInteractions(qualifications, policy, events);
    }

    @Test
    void selectedVersionWithMissingReferenceCannotAdvancePolicy() {
        doThrow(new Rbac3RuleViolation("RESOURCE_MANIFEST_CONFLICT")).when(activations).requireReferenceClosure(request);
        assertReason("RESOURCE_MANIFEST_CONFLICT");
        verifyNoInteractions(policy, events);
    }

    @Test
    void metadataPendingAndMismatchedSourceReceiptNeverActivate() {
        when(manifests.findVersion(SCOPE, "api", 1)).thenReturn(Optional.of(new PermissionManifestRepository.StoredManifest(1, candidate.manifest(),
                candidate.digests(), OPERATION, "METADATA_PENDING", null, 1)));
        assertReason("AUTH_SNAPSHOT_NOT_READY");
        when(manifests.findVersion(SCOPE, "api", 1)).thenReturn(Optional.of(candidate));
        when(manifests.sourceReceipt(SCOPE, "api", 1)).thenReturn(Optional.of(new SourceImportReceipt("300", OPERATION, SCOPE, "api", "1",
                source.sourceVersion(), source.digests(), "e".repeat(64), 1, 1, 1, NOW)));
        assertReason("RESOURCE_MANIFEST_CONFLICT");
        verifyNoInteractions(policy, events);
    }

    @Test
    void revokedDeploymentAuthorityAndAlreadyGrantedExpansionCannotPublish() {
        when(qualifications.requireTrusted(SCOPE, "api", 1, 301, NOW)).thenThrow(new Rbac3RuleViolation("SERVICE_IDENTITY_DENIED"));
        assertReason("SERVICE_IDENTITY_DENIED");
        doReturn(proof).when(qualifications).requireTrusted(SCOPE, "api", 1, 301, NOW);
        when(manifests.grantedCodes(SCOPE)).thenReturn(Set.of("app.read"));
        assertReason("SERVICE_IDENTITY_DENIED");
        verifyNoInteractions(policy, events);
    }

    @Test
    void descriptorReadRequiresReadCapabilityAndMatchingProducer() {
        var descriptor = new ActivationDescriptor(SCOPE, "1", OPERATION, "1", NOW, List.of(new ActivationDescriptor.ProducerVersion("api", "1",
                source.sourceVersion(), source.digests(), "301", "f".repeat(64))));
        when(activations.require(SCOPE, 1)).thenReturn(descriptor);
        assertEquals(descriptor, service.descriptor(SCOPE, "api", 1, caller()));
        verify(scopes).authorize(SCOPE, "api", caller(), PermissionCatalogCaller.Capability.READ_DESCRIPTOR, NOW);
        assertThrows(Rbac3RuleViolation.class, () -> service.descriptor(SCOPE, "other", 1, caller()));
    }

    @Test
    void administratorUsesUserFenceAndCannotApproveExpansionWithoutManagePermission() {
        var actor = mock(top.egon.cola.platform.tianquan.jianshen.starter.security.Rbac3UserDetails.class);
        when(actor.rbac3UserId()).thenReturn("90");
        when(scopes.lockOwner(SCOPE, "api")).thenReturn(owner(1));
        when(manifests.grantedCodes(SCOPE)).thenReturn(Set.of("app.read"));
        assertThrows(Rbac3RuleViolation.class, () -> service.activateAdministrator(request, actor));
        verifyNoInteractions(policy, events);
        when(actor.hasPermission(PermissionCatalogActivationService.MANAGE)).thenReturn(true);
        assertEquals("1", service.activateAdministrator(request, actor).activationVersion());
        verify(administration, org.mockito.Mockito.times(2)).require(SCOPE, actor, PermissionCatalogActivationService.ACTIVATE, NOW);
        verify(scopes, never()).authorize(any(), anyString(), any(), any(), any());
    }

    @Test
    void catalogEventIdentityUsesGlobalPolicyVersionAcrossGovernanceAndActivation() {
        when(policy.increment(eq(10L), anyString())).thenReturn(5L);
        var result = service.activate(request, caller());
        assertEquals("1", result.activationVersion());
        assertEquals("5", result.policyVersion());
        verify(events).enqueue(org.mockito.ArgumentMatchers.argThat(event -> event.safePayload().get("aggregateVersion").equals("5")
                && event.safePayload().get("catalogVersion").equals("1")));
    }

    private void assertReason(String reason) {
        assertEquals(reason, assertThrows(Rbac3RuleViolation.class, () -> service.activate(request, caller())).reasonCode());
        verify(activations, never()).save(any(), any(), anyString());
    }
}
