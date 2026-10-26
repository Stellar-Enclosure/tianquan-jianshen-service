package top.egon.cola.platform.tianquan.jianshen.admin.registration.catalog.service;

import top.egon.cola.platform.tianquan.jianshen.admin.registration.catalog.domain.convertor.PermissionCatalogJson;
import top.egon.cola.platform.tianquan.jianshen.admin.registration.catalog.domain.vo.DeploymentQualificationReceiptVO;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import top.egon.cola.platform.tianquan.jianshen.admin.audit.service.AuditQueryService;
import top.egon.cola.platform.tianquan.jianshen.admin.registration.catalog.domain.PermissionCatalogCaller;
import top.egon.cola.platform.tianquan.jianshen.admin.registration.catalog.repository.DeploymentQualificationRepository;
import top.egon.cola.platform.tianquan.jianshen.admin.registration.catalog.repository.PermissionCatalogScopeRepository;
import top.egon.cola.platform.tianquan.jianshen.admin.registration.catalog.repository.PermissionManifestRepository;
import top.egon.cola.platform.tianquan.jianshen.admin.shared.domain.DatabaseClock;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.CatalogActivationRequest;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.DeploymentQualificationRequest;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.PermissionManifestCanonicalizer;
import top.egon.cola.platform.tianquan.jianshen.core.rule.Rbac3RuleViolation;

import java.util.Optional;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;
import static top.egon.cola.platform.tianquan.jianshen.admin.registration.catalog.service.PermissionCatalogFixture.*;

class DeploymentQualificationTest {
    private final PermissionCatalogScopeRepository scopes = mock(PermissionCatalogScopeRepository.class);
    private final PermissionManifestRepository manifests = mock(PermissionManifestRepository.class);
    private final DeploymentQualificationRepository qualifications = mock(DeploymentQualificationRepository.class);
    private final AuditQueryService audit = mock(AuditQueryService.class);
    private final DatabaseClock clock = mock(DatabaseClock.class);
    private final PermissionCatalogJson json = new PermissionCatalogJson(new ObjectMapper().registerModule(new JavaTimeModule()));
    private final DeploymentQualificationService service = new DeploymentQualificationService(scopes, manifests, qualifications, json, audit, clock, () -> 301);
    private DeploymentQualificationRequest request;

    @BeforeEach
    void prepare() {
        when(clock.transactionNow()).thenReturn(NOW);
        when(scopes.authorize(any(), anyString(), any(), any(), any())).thenReturn(new PermissionCatalogScopeRepository.AuthorizedOwner(owner(1), grant()));
        var manifest = manifest();
        var digests = new PermissionManifestCanonicalizer().digests(manifest);
        request = new DeploymentQualificationRequest(SCOPE, "api", "1", "f".repeat(64), digests.manifestDigest(), digests.policyDigest(),
                "pipeline", "build", "refs/heads/main", manifest.artifact().commit(), "deployment",
                new DeploymentQualificationRequest.Readiness("f".repeat(64), digests.manifestDigest(), digests.policyDigest(), true, true, true, NOW));
        when(manifests.findVersion(SCOPE, "api", 1)).thenReturn(Optional.of(new PermissionManifestRepository.StoredManifest(
                1, manifest, digests, OPERATION, "READY", null, 2)));
    }

    @Test
    void exactSqlGrantedAuthorityCreatesImmutableBoundedProof() {
        var receipt = service.qualify(request, caller());
        assertEquals("301", receipt.qualificationId());
        assertEquals(NOW.plusSeconds(900), receipt.expiresAt());
        assertEquals(caller().issuer().toString(), receipt.issuer());
        assertEquals(request, receipt.attestation());
        verify(scopes).authorize(SCOPE, "api", caller(), PermissionCatalogCaller.Capability.QUALIFY_DEPLOYMENT, NOW);
        verify(qualifications).save(receipt);
        verify(audit).record(any());
    }

    @Test
    void aSourceRefOutsideCurrentGrantIsRejectedBeforeInspectingCandidate() {
        when(scopes.authorize(any(), anyString(), any(), any(), any())).thenReturn(new PermissionCatalogScopeRepository.AuthorizedOwner(owner(1),
                new PermissionCatalogScopeRepository.Grant(30, 2, Set.of("QUALIFY_DEPLOYMENT"), Set.of("refs/heads/release"), false)));
        assertEquals("SERVICE_IDENTITY_DENIED", assertThrows(Rbac3RuleViolation.class, () -> service.qualify(request, caller())).reasonCode());
        verifyNoInteractions(manifests, qualifications, audit);
    }

    @Test
    void missingCandidateAndStaleReadinessCannotCreateProof() {
        when(clock.transactionNow()).thenReturn(NOW.plusSeconds(301));
        assertEquals("RESOURCE_VERSION_CONFLICT", assertThrows(Rbac3RuleViolation.class, () -> service.qualify(request, caller())).reasonCode());
        when(clock.transactionNow()).thenReturn(NOW);
        when(manifests.findVersion(SCOPE, "api", 1)).thenReturn(Optional.empty());
        assertEquals("RESOURCE_NOT_FOUND", assertThrows(Rbac3RuleViolation.class, () -> service.qualify(request, caller())).reasonCode());
        verifyNoInteractions(qualifications, audit);
    }

    @Test
    void sameAttestationReturnsOriginalReceiptWithoutDuplicatingAuditOrQualification() {
        var original = new DeploymentQualificationReceiptVO("301", "a".repeat(64), request, caller().issuer().toString(), "pipeline",
                caller().principal().resourceUri().toString(), NOW, NOW.plusSeconds(60));
        when(qualifications.findCurrent(eq(SCOPE), eq("api"), anyString(), eq(caller()), eq(NOW))).thenReturn(Optional.of(original));
        assertEquals(original, service.qualify(request, caller()));
        verify(qualifications, never()).save(any());
        verifyNoInteractions(audit);
    }

    @Test
    void strictWireRejectsBooleanAndNumericCoercionAndUnknownFields() {
        String body = json.write(request);
        assertEquals(request, json.read(body, DeploymentQualificationRequest.class));
        assertThrows(IllegalArgumentException.class, () -> json.read(body.replace("\"componentsReady\":true", "\"componentsReady\":\"true\""), DeploymentQualificationRequest.class));
        assertThrows(IllegalArgumentException.class, () -> json.read(body.replace("\"producerVersion\":\"1\"", "\"producerVersion\":1"), DeploymentQualificationRequest.class));
        assertThrows(IllegalArgumentException.class, () -> json.read(body.replace("\"pipelineId\":", "\"unknown\":0,\"pipelineId\":"), DeploymentQualificationRequest.class));
        assertThrows(IllegalArgumentException.class, () -> json.read("{\"target\":" + json.write(SCOPE)
                + ",\"operationId\":\"" + OPERATION + "\",\"expectedActiveRevision\":\"0\",\"producers\":[]}", CatalogActivationRequest.class));
    }
}
