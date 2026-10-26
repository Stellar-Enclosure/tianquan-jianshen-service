package top.egon.cola.platform.tianquan.jianshen.starter.permission;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.*;
import top.egon.cola.platform.tianquan.shoubing.starter.security.IdpEndpointAuthenticationPolicy;
import java.time.*;
import java.util.*;
import static org.junit.jupiter.api.Assertions.*;

class PermissionAnonymousBoundaryTest {
    private final String key=PermissionAnonymousBoundary.LOGIN_TEXT_KEY;
    private final String path="/api/v1/tianshu/i18n/public/bundle";
    private final PermissionManifest.ResourceDefinition api=new PermissionManifest.ResourceDefinition(key,ResourceType.API,
            Map.of("methods",List.of("GET","HEAD"),"paths",List.of(path)),ResourceAccess.PUBLIC,null,null,
            List.of(PermissionManifest.PrincipalType.USER),List.of(),new PermissionManifest.I18nReference("auth","login"),DefinitionLifecycle.ACTIVE);
    private final PermissionManifest manifest=new PermissionManifest("1.0",new PermissionManifest.Application("platform","tianshu"),
            new PermissionManifest.Producer("tianshu-java",PermissionManifest.ProducerKind.JAVA,PermissionManifest.SnapshotMode.FULL,List.of("tianshu."),List.of("app"),List.of("app"),false),
            new PermissionManifest.Artifact("repo","a".repeat(40),"build","1"),List.of(),List.of(),List.of(api),List.of(),List.of());
    private PermissionAnonymousBoundary boundary(Set<String> configured,boolean publicPath){
        var registry=new PermissionPolicyRegistry(manifest,"a".repeat(64),Clock.systemUTC(),
                List.of(new CatalogScope("1","10","platform","tianshu","default","test")),Set.of(),configured);
        return new PermissionAnonymousBoundary(registry,()->new IdpEndpointAuthenticationPolicy(publicPath?List.of(path):List.of(),List.of()));
    }
    private MockHttpServletRequest request(String method,String url){var request=new MockHttpServletRequest(method,url);request.setParameter("locale","en");RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request));return request;}
    @AfterEach void clear(){RequestContextHolder.resetRequestAttributes();}
    @Test void reviewedPublicGetNeedsBothExplicitConfigurationAndPublicIdentityClassification(){
        request("GET",path);assertFalse(boundary(Set.of(),true).allows(key));assertFalse(boundary(Set.of(key),false).allows(key));
        assertTrue(boundary(Set.of(key),true).allows(key));
        request("POST",path);assertFalse(boundary(Set.of(key),true).allows(key));
        request("GET",path+"/other");assertFalse(boundary(Set.of(key),true).allows(key));
    }
    @Test void enterpriseParametersOrApi008NeverUseTheAnonymousBoundary(){
        request("GET",path).setParameter("tenantId","10");assertFalse(boundary(Set.of(key),true).allows(key));
        request("GET","/api/v1/authorization/effective-permissions");assertFalse(boundary(Set.of(key),true).allows(key));
        assertThrows(IllegalArgumentException.class,()->boundary(Set.of("tianshu.api.auth.bootstrap"),true));
    }
}
