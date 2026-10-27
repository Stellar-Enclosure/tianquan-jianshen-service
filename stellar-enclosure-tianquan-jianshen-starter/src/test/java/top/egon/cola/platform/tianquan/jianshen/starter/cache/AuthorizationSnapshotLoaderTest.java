package top.egon.cola.platform.tianquan.jianshen.starter.cache;

import org.junit.jupiter.api.Test;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.*;
import top.egon.cola.platform.tianquan.jianshen.starter.client.Rbac3AuthorizationClient;
import top.egon.cola.platform.tianquan.shoubing.contract.IdentityPrincipal;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;
import static top.egon.cola.platform.tianquan.jianshen.starter.permission.PermissionRuntimeFixture.*;

class AuthorizationSnapshotLoaderTest {
    record Payload(String value) { }
    private final PermissionManifest manifest=manifest(List.of(field(Payload.class,"value",ResourceAccess.PUBLIC,null)));
    @Test void everyConcurrentBoundaryFetchesTheCurrentSqlAuthority() throws Exception {
        AtomicInteger calls=new AtomicInteger();
        var loader=new AuthorizationSnapshotLoader((system,user)->{calls.incrementAndGet();return snapshot(manifest,Set.of("order:read"));},"shop",CLOCK);
        try(var workers=Executors.newFixedThreadPool(4)) {
            var results=new ArrayList<Future<?>>();
            for(int index=0;index<8;index++) results.add(workers.submit(()->loader.load(USER,"original-proof")));
            for(var result:results) result.get(5,TimeUnit.SECONDS);
        }
        assertEquals(8,calls.get());
    }
    @Test void cachedAuthorizationCannotProvideDatabaseFailureGrace() {
        var cache=mock(AuthorizationSnapshotCache.class);
        var loader=new SingleFlightSnapshotLoader(cache,(system,user)->{
            throw new Rbac3AuthorizationClient.AuthorizationUnavailableException("SQL_UNAVAILABLE");
        },"shop",Duration.ofSeconds(30),CLOCK);
        assertThrows(Rbac3AuthorizationClient.AuthorizationUnavailableException.class,()->loader.load(USER,"proof"));
        verifyNoInteractions(cache);
    }
    @Test void differentDeviceProofsAlwaysReadTheSameCurrentAccountPermissions() {
        var current=new java.util.concurrent.atomic.AtomicReference<>(snapshot(manifest,Set.of("order:read")));
        var loader=new AuthorizationSnapshotLoader((system,user)->current.get(),"shop",CLOCK);
        assertEquals(Set.of("order:read"),loader.load(USER,"browser-proof").permissions());
        current.set(snapshot(manifest,Set.of("order:write")));
        assertEquals(Set.of("order:write"),loader.load(USER,"app-proof").permissions());
        assertEquals(Set.of("order:write"),loader.load(USER,"browser-proof").permissions());
    }
    @Test void foreignSubjectSnapshotIsRejectedEvenWhenFresh() {
        var other=new IdentityPrincipal("31",USER.tenantId(),"41",USER.audience(),USER.issuedAt(),USER.expiresAt(),USER.authenticationContext());
        var loader=new AuthorizationSnapshotLoader((system,user)->snapshot(manifest,Set.of()),"shop",CLOCK);
        assertThrows(Rbac3AuthorizationClient.AuthorizationDeniedException.class,()->loader.load(other,"proof"));
    }
    @Test void anOriginalVerifiedUserProofIsAlwaysRequired() {
        var client=mock(Rbac3AuthorizationClient.class);
        var loader=new AuthorizationSnapshotLoader(client,"shop",CLOCK);
        assertThrows(Rbac3AuthorizationClient.AuthorizationUnavailableException.class,()->loader.load(USER,null));
        verifyNoInteractions(client);
    }
}
