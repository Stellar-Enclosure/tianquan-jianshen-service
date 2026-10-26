package top.egon.cola.platform.tianquan.jianshen.admin.authorization.runtime.catalog;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.http.converter.json.MappingJackson2HttpMessageConverter;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerAdapter;
import org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerMapping;
import top.egon.cola.platform.tianquan.jianshen.contract.authorization.*;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.*;
import top.egon.cola.platform.tianquan.jianshen.starter.permission.*;
import top.egon.cola.platform.tianquan.jianshen.starter.security.*;
import top.egon.cola.platform.tianquan.jianshen.starter.web.Rbac3AuthorizationExceptionHandler;
import top.egon.cola.platform.tianquan.shoubing.contract.*;
import top.egon.cola.platform.tianquan.shoubing.starter.security.VerifiedUserTokenCarrier;
import java.time.*;
import java.util.*;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

class FieldCatalogControllerTest {
    static class Input { public String name; @JsonProperty(access=JsonProperty.Access.READ_ONLY) public String calculated; public Nested nested; }
    static class Nested { public String detail; }
    static class Output { public String result; }
    @RestController static class Inputs {
        @PostMapping("/test/input") void write(@RequestBody Input input) { }
    }
    private static final Instant NOW=Instant.parse("2026-10-25T00:00:00Z");
    private static final String KEY="tianquan-jianshen.api.authorization.fields";
    private static final CatalogScope SCOPE=new CatalogScope("10","20","permission","tianquan-jianshen","default","test");
    private final PermissionManifest manifest=new PermissionManifest("1.0",new PermissionManifest.Application("permission","tianquan-jianshen"),
            new PermissionManifest.Producer("r-java",PermissionManifest.ProducerKind.JAVA,PermissionManifest.SnapshotMode.FULL,List.of("tianquan-jianshen."),List.of("r"),List.of("r"),false),
            new PermissionManifest.Artifact("https://example.com/repo","a".repeat(40),"b1","1"),List.of(),List.of(),List.of(
            new PermissionManifest.ResourceDefinition(KEY,ResourceType.API,Map.of("methods",List.of("GET"),"paths",List.of("/api/v1/authorization/field-catalog")),
                    ResourceAccess.PUBLIC,null,null,List.of(PermissionManifest.PrincipalType.USER),List.of(),new PermissionManifest.I18nReference("runtime","fields"),DefinitionLifecycle.ACTIVE),
            field(Input.class,"name"),field(Input.class,"calculated"),field(Nested.class,"detail"),field(Output.class,"result")),List.of(),List.of());
    private final MockMvc mvc;
    @SuppressWarnings("unchecked") FieldCatalogControllerTest() {
        var registry=new PermissionPolicyRegistry(manifest,"a".repeat(64),Clock.fixed(NOW,ZoneOffset.UTC),List.of(SCOPE));
        var users=new CurrentRbac3User();
        var catalog=new PermissionFieldCatalog(registry,new CurrentEffectivePermissionView(users,registry,Clock.fixed(NOW,ZoneOffset.UTC)),users);
        ObjectProvider<RequestMappingHandlerAdapter> adapters=mock(ObjectProvider.class);
        ObjectProvider<RequestMappingHandlerMapping> routes=mock(ObjectProvider.class);
        mvc=MockMvcBuilders.standaloneSetup(new FieldCatalogController(catalog,adapters,routes),new Inputs())
                .setMessageConverters(new MappingJackson2HttpMessageConverter(new ObjectMapper()))
                .setControllerAdvice(new Rbac3AuthorizationExceptionHandler(),new InvalidInputAdvice())
                .addFilter((req,res,chain)->{VerifiedUserTokenCarrier.set((jakarta.servlet.http.HttpServletRequest)req,"verified-user");chain.doFilter(req,res);}).build();
        when(adapters.getObject()).thenReturn(mvc.getDispatcherServlet().getWebApplicationContext().getBean(RequestMappingHandlerAdapter.class));
        when(routes.getObject()).thenReturn(mvc.getDispatcherServlet().getWebApplicationContext().getBean(RequestMappingHandlerMapping.class));
    }
    @AfterEach void clear(){SecurityContextHolder.clearContext();}
    @Test void actualRegisteredRequestDtoGraphDeterminesInputBinding() throws Exception {
        authenticate();
        mvc.perform(get("/api/v1/authorization/field-catalog").param("keys","tianquan-jianshen.field.Input.name","tianquan-jianshen.field.Input.calculated", "tianquan-jianshen.field.Nested.detail","tianquan-jianshen.field.Output.result"))
                .andExpect(status().isOk()).andExpect(header().string("Cache-Control","no-store"))
                .andExpect(jsonPath("$.data.catalogVersion").value("1"))
                .andExpect(jsonPath("$.data.fields['tianquan-jianshen.field.Input.name'].inputBinding").value(true))
                .andExpect(jsonPath("$.data.fields['tianquan-jianshen.field.Input.calculated'].inputBinding").value(false))
                .andExpect(jsonPath("$.data.fields['tianquan-jianshen.field.Nested.detail'].inputBinding").value(true))
                .andExpect(jsonPath("$.data.fields['tianquan-jianshen.field.Output.result'].inputBinding").value(false));
    }
    @Test void userProofAndFiniteKeyQueryRemainMandatory() throws Exception {
        mvc.perform(get("/api/v1/authorization/field-catalog").param("keys","tianquan-jianshen.field.Input.name")).andExpect(status().isUnauthorized());
        authenticate();
        mvc.perform(get("/api/v1/authorization/field-catalog").param("keys","tianquan-jianshen.field.Input.name").param("subject","other"))
                .andExpect(status().isBadRequest());
        mvc.perform(get("/api/v1/authorization/field-catalog").param("keys","foreign.field.name")).andExpect(status().isBadRequest());
    }
    private void authenticate() {
        var identity=new IdentityPrincipal("30","20","40",Set.of("https://api.example/r"),NOW.minusSeconds(5),NOW.plusSeconds(120),AuthenticationContext.password());
        var view=new EffectivePermissionSnapshot("https://idp.example/tenants/20","30",SCOPE,"1","2","3",new EffectivePermissionSnapshot.ActiveRoleContext("tianquan-jianshen",List.of(),List.of()),List.of(),NOW.plusSeconds(30));
        var d=new PermissionManifestCanonicalizer().digests(manifest);
        var snapshot=new SystemAuthorizationSnapshot("20","30","60","tianquan-jianshen",2,3,List.of(),null,null,Set.of(),manifest.resources().stream().map(PermissionManifest.ResourceDefinition::key).collect(java.util.stream.Collectors.toSet()),Map.of(),Map.of(),"s",NOW,view.snapshotExpiresAt(),view,new RuntimePolicyBinding("r-java","1","a".repeat(64),d.policyDigest(),d.manifestDigest()));
        SecurityContextHolder.getContext().setAuthentication(new Rbac3AuthenticationToken(new Rbac3UserDetails(identity,snapshot)));
    }
    private PermissionManifest.ResourceDefinition field(Class<?> owner,String property) {
        return new PermissionManifest.ResourceDefinition("tianquan-jianshen.field."+owner.getSimpleName()+"."+property,ResourceType.FIELD,Map.of("dto",owner.getCanonicalName(),"property",property),ResourceAccess.PUBLIC,null,null,List.of(PermissionManifest.PrincipalType.USER),List.of(),new PermissionManifest.I18nReference("runtime",property),DefinitionLifecycle.ACTIVE);
    }
    @RestControllerAdvice static class InvalidInputAdvice {
        @ExceptionHandler(IllegalArgumentException.class) org.springframework.http.ResponseEntity<Void> invalid(){return org.springframework.http.ResponseEntity.badRequest().build();}
    }
}
