package top.egon.cola.platform.tianquan.jianshen.admin.registration.catalog.service;

import top.egon.cola.platform.tianquan.jianshen.admin.registration.catalog.repository.CatalogAdministrationGuard;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import top.egon.cola.platform.tianquan.jianshen.admin.registration.catalog.repository.PermissionCatalogQueryRepository;
import top.egon.cola.platform.tianquan.jianshen.admin.registration.catalog.repository.PermissionCatalogScopeRepository;
import top.egon.cola.platform.tianquan.jianshen.admin.registration.catalog.repository.PermissionManifestRepository;
import top.egon.cola.platform.tianquan.jianshen.admin.registration.catalog.repository.PermissionSourceOutboxRepository;
import top.egon.cola.platform.tianquan.jianshen.admin.shared.domain.DatabaseClock;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.PermissionManifestCanonicalizer;
import top.egon.cola.platform.tianquan.jianshen.starter.security.Rbac3UserDetails;

import java.util.List;
import java.util.Optional;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;
import static top.egon.cola.platform.tianquan.jianshen.admin.registration.catalog.service.PermissionCatalogFixture.*;

class PermissionCatalogQueryTest {
    private final CatalogAdministrationGuard guard = mock(CatalogAdministrationGuard.class);
    private final PermissionCatalogScopeRepository scopes = mock(PermissionCatalogScopeRepository.class);
    private final PermissionCatalogQueryRepository queries = mock(PermissionCatalogQueryRepository.class);
    private final PermissionManifestRepository manifests = mock(PermissionManifestRepository.class);
    private final PermissionSourceOutboxRepository outbox = mock(PermissionSourceOutboxRepository.class);
    private final DatabaseClock clock = mock(DatabaseClock.class);
    private final Rbac3UserDetails actor = mock(Rbac3UserDetails.class);
    private final PermissionCatalogQueryService service = new PermissionCatalogQueryService(guard, scopes, queries, manifests, outbox, clock);

    @BeforeEach
    void prepare() {
        when(clock.transactionNow()).thenReturn(NOW);
        when(scopes.readExistingOwner(SCOPE, "api")).thenReturn(owner(2));
    }

    @Test
    void boundedCandidatePageReportsDeadDeliveryWithoutLoadingManifestBodies() {
        var digests = new PermissionManifestCanonicalizer().digests(manifest());
        var newest = new PermissionCatalogQueryRepository.Candidate("2", digests, "METADATA_PENDING", null, OPERATION,
                "repo", "a".repeat(40), "build", "1", NOW, null);
        var oldest = new PermissionCatalogQueryRepository.Candidate("1", digests, "READY", null, OPERATION,
                "repo", "a".repeat(40), "build", "1", NOW.minusSeconds(10), null);
        when(queries.candidates(SCOPE, "api", 0, 1, NOW)).thenReturn(List.of(new PermissionCatalogQueryRepository.StoredCandidate(newest, 3),
                new PermissionCatalogQueryRepository.StoredCandidate(oldest, 2)));
        when(outbox.dead(SCOPE, "api", 2, 3)).thenReturn(true);
        var page = service.candidates(SCOPE, "api", 0, 1, actor);
        assertEquals(1, page.candidates().size());
        assertEquals("FAILED", page.candidates().getFirst().state());
        assertEquals("2", page.nextBeforeVersion());
        verify(guard).requireRead(SCOPE, actor, PermissionCatalogActivationService.READ, NOW);
        verify(scopes, never()).lockExistingOwner(any(), anyString());
        verifyNoInteractions(manifests);
    }

    @Test
    void diffIsRecomputedAgainstCurrentActiveAndCurrentlyGrantedCodes() {
        var manifest = manifest();
        var digests = new PermissionManifestCanonicalizer().digests(manifest);
        when(manifests.findVersion(SCOPE, "api", 2)).thenReturn(Optional.of(new PermissionManifestRepository.StoredManifest(2, manifest, digests, OPERATION, "READY", null, 2)));
        when(manifests.grantedCodes(SCOPE)).thenReturn(Set.of("app.read"));
        var diff = service.diff(SCOPE, "api", 2, actor);
        assertEquals("0", diff.expectedActiveRevision());
        assertTrue(diff.diff().authorizationExpansion());
        verify(manifests).activeManifest(SCOPE, "api");
        verifyNoInteractions(outbox);
    }
}
