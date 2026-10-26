package top.egon.cola.platform.tianquan.jianshen.admin.authorization.runtime.catalog;

import org.junit.jupiter.api.Test;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.CatalogScope;
import top.egon.cola.platform.tianquan.jianshen.core.rule.Rbac3RuleViolation;
import top.egon.cola.platform.tianquan.shoubing.contract.*;
import top.egon.cola.platform.tianquan.shoubing.starter.security.*;
import java.net.URI;
import java.time.*;
import java.util.*;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class RuntimeProofBindingTest {
    static final Instant NOW=Instant.parse("2026-10-25T00:00:00Z");
    static final URI ISSUER=URI.create("https://idp.example/tenants/20");
    static final URI RESOURCE=URI.create("https://api.example/shop");
    static final URI RECEIVER=URI.create("https://api.example/rbac");
    static final CatalogScope SCOPE=new CatalogScope("10","20","commerce","shop","default","test");
    static PermissionRuntimeProperties.Binding binding() {
        return new PermissionRuntimeProperties.Binding(SCOPE,RESOURCE,ISSUER,"shop-runtime","shop-client","commerce","shop","test",
                RECEIVER,"shop-java","1","a".repeat(64),"b".repeat(64),"c".repeat(64),true);
    }
    static IdentityPrincipal user() {
        return new IdentityPrincipal("30","20","40",Set.of(RESOURCE.toASCIIString()),NOW.minusSeconds(10),NOW.plusSeconds(100),
                AuthenticationContext.of("PASSWORD",NOW.minusSeconds(20)));
    }
    static ServiceIdentityPrincipal caller(String client, String environment) {
        return new ServiceIdentityPrincipal(client,"20",client,"45",RECEIVER,0,Set.of("service:authorization:snapshot"),
                "commerce","shop",environment,"credential",NOW.minusSeconds(10),NOW.plusSeconds(100),"shop-client",ServiceTokenContext.TENANT);
    }
    private final IdpJwtVerifier verifier=mock(IdpJwtVerifier.class);
    private final PermissionRuntimeProofService service=new PermissionRuntimeProofService(
            new PermissionRuntimeProperties(Duration.ofSeconds(30),List.of(binding())),Map.of(RESOURCE,verifier),Clock.fixed(NOW,ZoneOffset.UTC));
    @Test void exactServiceTupleSelectsOriginalUserAudienceAndFullScope() {
        when(verifier.verifyUser("original")).thenReturn(new AccessTokenVerification.Valid<>(user(),Set.of(),null,ISSUER));
        var result=service.service(caller("shop-runtime","test"),ISSUER,"shop","original");
        assertEquals(SCOPE,result.binding().scope()); assertEquals("30",result.user().subject());
        verify(verifier).verifyUser("original");
    }
    @Test void callerClientEnvironmentIssuerOrApplicationCannotSelectAnotherScope() {
        for (var call : List.<Runnable>of(
                ()->service.service(caller("other-client","test"),ISSUER,"shop","original"),
                ()->service.service(caller("shop-runtime","production"),ISSUER,"shop","original"),
                ()->service.service(caller("shop-runtime","test"),URI.create("https://evil.example/20"),"shop","original"),
                ()->service.service(caller("shop-runtime","test"),ISSUER,"admin","original"))) {
            assertThrows(Rbac3RuleViolation.class,call::run);
        }
        verifyNoInteractions(verifier);
    }
    @Test void sameTenantTextCannotJoinDifferentVerifiedIssuers() {
        when(verifier.verifyUser("original")).thenReturn(new AccessTokenVerification.Valid<>(user(),Set.of(),null,URI.create("https://another.example/20")));
        assertEquals("IDENTITY_SUBJECT_MISMATCH",assertThrows(Rbac3RuleViolation.class,
                ()->service.service(caller("shop-runtime","test"),ISSUER,"shop","original")).reasonCode());
    }
    @Test void databaseFailureRemainsUnavailableRatherThanAnEmptyPermissionSuccess() {
        when(verifier.verifyUser("original")).thenReturn(new AccessTokenVerification.Unavailable<>("IDENTITY_AUTHORITY_UNAVAILABLE"));
        assertEquals("AUTH_RUNTIME_UNAVAILABLE",assertThrows(Rbac3RuleViolation.class,
                ()->service.service(caller("shop-runtime","test"),ISSUER,"shop","original")).reasonCode());
    }
    @Test void localViewMustMatchTheAlreadyVerifiedOriginalToken() {
        var another=new IdentityPrincipal("31","20","41",user().audience(),user().issuedAt(),user().expiresAt(),user().authenticationContext());
        when(verifier.verifyUser("original")).thenReturn(new AccessTokenVerification.Valid<>(another,Set.of(),null,ISSUER));
        assertEquals("IDENTITY_SUBJECT_MISMATCH",assertThrows(Rbac3RuleViolation.class,()->service.local(user(),"original")).reasonCode());
    }
}
