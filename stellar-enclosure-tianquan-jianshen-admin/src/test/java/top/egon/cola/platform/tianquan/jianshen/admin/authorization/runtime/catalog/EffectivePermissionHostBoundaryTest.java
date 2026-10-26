package top.egon.cola.platform.tianquan.jianshen.admin.authorization.runtime.catalog;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.json.MappingJackson2HttpMessageConverter;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.bind.annotation.*;
import top.egon.cola.platform.tianquan.jianshen.contract.authorization.*;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.*;
import top.egon.cola.platform.tianquan.jianshen.starter.permission.*;
import top.egon.cola.platform.tianquan.jianshen.starter.security.*;
import top.egon.cola.platform.tianquan.jianshen.starter.web.Rbac3AuthorizationExceptionHandler;
import top.egon.cola.platform.tianquan.jianshen.admin.shared.controller.Rbac3ApiExceptionHandler;
import top.egon.cola.platform.tianquan.shoubing.contract.*;
import top.egon.cola.platform.tianquan.shoubing.starter.security.*;
import java.net.URI;
import java.time.*;
import java.util.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;
import static top.egon.cola.platform.tianquan.jianshen.admin.authorization.runtime.catalog.RuntimeCatalogPostgresqlFixture.*;

/** Host-local API-008 uses only the filter's current trusted view and never forwards a differently scoped browser token. */
class EffectivePermissionHostBoundaryTest {
    private static final String PATH="/api/v1/authorization/effective-permissions";
    private final IdentityPrincipal identity=new IdentityPrincipal("9001","10","9002",Set.of("https://app.example"),NOW.minusSeconds(10),NOW.plusSeconds(300),AuthenticationContext.of("PASSWORD",NOW));
    private final PermissionPolicyRegistry registry=new PermissionPolicyRegistry(manifest(),"f".repeat(64),Clock.fixed(NOW,ZoneOffset.UTC),List.of(SCOPE));
    @AfterEach void clear(){SecurityContextHolder.clearContext();}
    private SystemAuthorizationSnapshot snapshot(){
        var digests=new PermissionManifestCanonicalizer().digests(manifest());
        var view=new EffectivePermissionSnapshot("https://issuer.example/tenants/10","9001",SCOPE,"1","2","3",
                new EffectivePermissionSnapshot.ActiveRoleContext("app",List.of("40"),List.of("40")),List.of("app.read"),NOW.plusSeconds(30));
        return new SystemAuthorizationSnapshot("10","9001","90","app",2,3,List.of("40"),null,null,Set.of("app.read"),Set.of("app.read"),Map.of(),Map.of(),"sum",NOW,view.snapshotExpiresAt(),view,
                new RuntimePolicyBinding("api","1","f".repeat(64),digests.policyDigest(),digests.manifestDigest()));
    }
    private void user(){SecurityContextHolder.getContext().setAuthentication(new Rbac3AuthenticationToken(new Rbac3UserDetails(identity,snapshot())));}
    private MockMvc mvc(Instant now){
        var controller=new HostController(new CurrentEffectivePermissionView(new CurrentRbac3User(),registry,Clock.fixed(now,ZoneOffset.UTC)));
        return MockMvcBuilders.standaloneSetup(controller).setControllerAdvice(new Rbac3AuthorizationExceptionHandler(),new Rbac3ApiExceptionHandler())
                .setMessageConverters(new MappingJackson2HttpMessageConverter(new ObjectMapper().findAndRegisterModules()))
                .addFilter((request,response,chain)->{VerifiedUserTokenCarrier.set((HttpServletRequest)request,"original-verified-proof");chain.doFilter(request,response);}).build();
    }
    @Test void currentUserGetsOnlyItsAlreadyVerifiedScopeAndVersions()throws Exception{
        user();mvc(NOW).perform(get(PATH)).andExpect(status().isOk()).andExpect(jsonPath("data.subject").value("9001"))
                .andExpect(jsonPath("data.catalogScope.catalogScopeId").value("1")).andExpect(jsonPath("data.catalogScope.applicationCode").value("app"))
                .andExpect(jsonPath("data.authVersion").value("2")).andExpect(header().string("Cache-Control","no-store"));
    }
    @Test void subjectTenantScopeQueriesCannotRetargetTheView()throws Exception{
        user();for(String parameter:List.of("subject","tenantId","catalogScopeId","applicationCode")){
            mvc(NOW).perform(get(PATH).param(parameter,"attacker")).andExpect(status().isBadRequest());
        }
    }
    @Test void serviceAndAnonymousHeadersCannotBecomeAUserView()throws Exception{
        var service=new ServiceIdentityPrincipal("caller","10","caller","9003",URI.create("https://app.example"),0,
                Set.of("service:authorization:policy"),"biz","caller","test","credential",NOW.minusSeconds(1),NOW.plusSeconds(60));
        SecurityContextHolder.getContext().setAuthentication(new IdpAuthenticationToken(service));
        mvc(NOW).perform(get(PATH)).andExpect(status().isUnauthorized());
        SecurityContextHolder.clearContext();mvc(NOW).perform(get(PATH).header("X-User-Id","9001").header("X-Tenant-Id","10")).andExpect(status().isUnauthorized());
    }
    @Test void anExpiredSqlViewNeverBecomesAValidEmptyResponse()throws Exception{
        user();mvc(NOW.plusSeconds(40)).perform(get(PATH)).andExpect(status().isServiceUnavailable());
    }
    @RestController static class HostController{
        private final CurrentEffectivePermissionView views;
        HostController(CurrentEffectivePermissionView views){this.views=views;}
        @GetMapping(PATH) ResponseEntity<top.egon.cola.component.common.core.pojo.ResultRecord<EffectivePermissionSnapshot>> current(HttpServletRequest request){
            return ResponseEntity.ok().header("Cache-Control","no-store").body(top.egon.cola.component.common.core.pojo.ResultRecord.success(views.current(request,"app.read")));
        }
    }
}
