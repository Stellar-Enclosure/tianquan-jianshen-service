package top.egon.cola.platform.tianquan.jianshen.starter.permission;

import org.junit.jupiter.api.Test;
import top.egon.cola.platform.tianquan.jianshen.starter.client.Rbac3AuthorizationClient;
import top.egon.cola.platform.tianquan.shoubing.starter.security.IdpObservedVerificationComponent;
import top.egon.cola.platform.tianquan.shoubing.starter.security.domain.IdpAuthorizationObservationContextBO;
import top.egon.cola.platform.tianquan.shoubing.starter.security.domain.TokenAuditProofBO;
import top.egon.cola.platform.tianquan.shoubing.starter.security.rpc.IdpRpcSecurityContext;
import java.net.URI;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;
import static top.egon.cola.platform.tianquan.jianshen.starter.permission.PermissionRuntimeFixture.*;

class PermissionDenialAuditTest {
    private final IdpObservedVerificationComponent observations=mock(IdpObservedVerificationComponent.class);
    private final PermissionDenialAudit audit=new PermissionDenialAudit(()->observations);
    private final TokenAuditProofBO proof=new TokenAuditProofBO(URI.create("https://idp.example/tenants/20"),
            URI.create("https://api.example/shop"),"a".repeat(64),null,"b".repeat(64));
    @Test void rpcApiAndFieldDenialsShareTheExistingStrictReceiptMarker(){
        when(observations.enabled()).thenReturn(true);when(observations.authorizationDenied(proof)).thenReturn(true);
        var marker=new IdpAuthorizationObservationContextBO();
        try{
            IdpRpcSecurityContext.with(USER,"proof",proof,marker).run(()->{
                assertInstanceOf(org.springframework.security.authorization.AuthorizationDeniedException.class,audit.denied("PERMISSION_DENIED"));
                assertInstanceOf(org.springframework.security.authorization.AuthorizationDeniedException.class,audit.denied("FIELD_ACCESS_DENIED"));
            });
            verify(observations,times(1)).authorizationDenied(proof);assertTrue(marker.isConfirmed());
        }finally{marker.close();}
    }
    @Test void missingCommittedAuditReceiptRemainsUnavailable(){
        when(observations.enabled()).thenReturn(true);when(observations.authorizationDenied(proof)).thenReturn(false);
        var marker=new IdpAuthorizationObservationContextBO();
        try{
            IdpRpcSecurityContext.with(USER,"proof",proof,marker).run(()->{
                assertInstanceOf(Rbac3AuthorizationClient.AuthorizationUnavailableException.class,audit.denied("FIELD_ACCESS_DENIED"));
                assertInstanceOf(Rbac3AuthorizationClient.AuthorizationUnavailableException.class,audit.denied("PERMISSION_DENIED"));
            });
            verify(observations,times(1)).authorizationDenied(proof);assertFalse(marker.isConfirmed());
        }finally{marker.close();}
    }
}
