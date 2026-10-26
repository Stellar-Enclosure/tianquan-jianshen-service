package top.egon.cola.platform.tianquan.jianshen.admin.authorization.runtime.catalog;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;
import org.springframework.http.converter.json.MappingJackson2HttpMessageConverter;
import org.springframework.mock.web.MockMultipartFile;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;
import top.egon.cola.component.common.desensitize.strategy.SensitiveStrategyRegistry;
import top.egon.cola.platform.tianquan.jianshen.contract.authorization.*;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.*;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.annotation.PermissionResource;
import top.egon.cola.platform.tianquan.jianshen.starter.cache.SingleFlightSnapshotLoader;
import top.egon.cola.platform.tianquan.jianshen.starter.client.Rbac3AuthorizationClient;
import top.egon.cola.platform.tianquan.jianshen.starter.field.*;
import top.egon.cola.platform.tianquan.jianshen.starter.permission.*;
import top.egon.cola.platform.tianquan.jianshen.starter.security.*;
import top.egon.cola.platform.tianquan.jianshen.starter.web.Rbac3AuthorizationExceptionHandler;
import top.egon.cola.platform.tianquan.shoubing.contract.*;
import top.egon.cola.platform.tianquan.shoubing.starter.security.*;
import java.net.URI;
import java.time.*;
import java.util.*;
import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/** Real MVC JSON/multipart binder and business method; token verification is covered by the identity and proof tests. */
class PermissionFieldHttpBoundaryTest {
    private static final Instant NOW=Instant.parse("2026-10-25T00:00:00Z");
    private static final Clock CLOCK=Clock.fixed(NOW,ZoneOffset.UTC);
    private static final CatalogScope SCOPE=new CatalogScope("10","20","commerce","shop","default","test");
    private static final String WRITE="service:object:write";
    public static class Input { public String name; @JsonProperty(access=JsonProperty.Access.READ_ONLY) public String calculated; }
    private final PermissionRequirement fieldWrite=new PermissionRequirement(PermissionMode.ALL,List.of("field:write"));
    private final PermissionManifest manifest=new PermissionManifest("1.0",new PermissionManifest.Application("commerce","shop"),
            new PermissionManifest.Producer("shop-java",PermissionManifest.ProducerKind.JAVA,PermissionManifest.SnapshotMode.FULL,List.of("shop."),List.of("app"),List.of("app"),false),
            new PermissionManifest.Artifact("https://example.com/repo","a".repeat(40),"build-1","1"),List.of(),List.of("order:write","field:write"),
            List.of(api("json","/json"),api("upload","/upload"),field("name",ResourceAccess.PROTECTED,
                    new PermissionManifest.FieldPolicy(PermissionManifest.JsonFieldType.STRING,null,null,fieldWrite,null)),field("calculated",ResourceAccess.PUBLIC,null)),List.of(),List.of());
    private long policyVersion=3;
    private boolean revokeFieldAtMethodBoundary;
    private boolean changeServicePolicyAtMethodBoundary;
    private int servicePolicyReads;
    private Set<String> codes=Set.of("order:write","field:write");
    private final IdentityPrincipal identity=new IdentityPrincipal("30","20","40",Set.of("https://api.example/shop"),NOW.minusSeconds(10),NOW.plusSeconds(100),AuthenticationContext.of("PASSWORD",NOW));
    private final PermissionPolicyRegistry registry=new PermissionPolicyRegistry(manifest,"a".repeat(64),CLOCK,List.of(SCOPE));
    private final Rbac3AuthorizationClient client=new Rbac3AuthorizationClient(){
        @Override public SystemAuthorizationSnapshot fetch(String system,IdentityPrincipal user){
            if(revokeFieldAtMethodBoundary){codes=Set.of("order:write");policyVersion++;}
            return userSnapshot();
        }
        @Override public ServicePolicySnapshot fetchPolicy(String system,ServiceIdentityPrincipal service){return new ServicePolicySnapshot(SCOPE,"1",
                changeServicePolicyAtMethodBoundary && ++servicePolicyReads > 1 ? "4" : "3",binding(),keys(),NOW.plusSeconds(30));}
    };
    private final PermissionServicePolicyGuard services=new PermissionServicePolicyGuard(registry,client,"shop",CLOCK);
    private final CurrentRbac3User users=new CurrentRbac3User();
    private final top.egon.cola.platform.tianquan.jianshen.starter.autoconfigure.Rbac3StarterProperties.UserScopePolicyProperties userPolicy =
            new top.egon.cola.platform.tianquan.jianshen.starter.autoconfigure.Rbac3StarterProperties.UserScopePolicyProperties().setEnabled(true)
                    .setPermissionScopes(Map.of("order:write", Set.of("user:write"), "field:write", Set.of("user:write")));
    private final PermissionExecutionGuard execution=new PermissionExecutionGuard(registry,users,new SingleFlightSnapshotLoader(client,"shop",CLOCK),services,userPolicy);
    private final PermissionFieldBindingGuard fields=new PermissionFieldBindingGuard(registry,users,()->services,userPolicy);
    private final Endpoint endpoint=new Endpoint(execution,fields);
    private final MockMvc mvc;
    PermissionFieldHttpBoundaryTest(){
        var mapper=new ObjectMapper();
        var converter = new MappingJackson2HttpMessageConverter(mapper);
        new top.egon.cola.platform.tianquan.jianshen.admin.config.runtime.Rbac3PermissionMvcConfiguration(
                new PermissionJsonMapperFactory(users, SensitiveStrategyRegistry.defaults(), registry, fields), mapper)
                .extendMessageConverters(List.of(converter));
        assertNotSame(mapper, converter.getObjectMapper());
        assertFalse(mapper.getRegisteredModuleIds().contains("Rbac3FieldJacksonModule"));
        mvc=MockMvcBuilders.standaloneSetup(endpoint).setControllerAdvice(new Rbac3AuthorizationExceptionHandler())
                .setMessageConverters(converter)
                .addFilter((request,response,chain)->{VerifiedUserTokenCarrier.set((jakarta.servlet.http.HttpServletRequest)request,"original-proof");chain.doFilter(request,response);}).build();
    }
    @AfterEach void clear(){SecurityContextHolder.clearContext();}
    @Test void userNullWriteFailsBeforeTheActualBusinessMethod() throws Exception {
        codes=Set.of("order:write");user();mvc.perform(post("/json").contentType(MediaType.APPLICATION_JSON).content("{\"name\":null}")).andExpect(status().isForbidden());
        assertEquals(0,endpoint.writes);
        codes=Set.of("order:write","field:write");user();mvc.perform(post("/json").contentType(MediaType.APPLICATION_JSON).content("{\"name\":null}")).andExpect(status().isOk());
        assertEquals(1,endpoint.writes);
    }
    @Test void serviceScopeAndReadOnlyBindingAreCheckedOnTheActualJsonRoute() throws Exception {
        service(Set.of("service:object:read","service:field:write"));
        mvc.perform(post("/json").contentType(MediaType.APPLICATION_JSON).content("{\"name\":\"x\"}")).andExpect(status().isForbidden());
        service(Set.of(WRITE,"service:field:write"));
        mvc.perform(post("/json").contentType(MediaType.APPLICATION_JSON).content("{\"calculated\":\"x\"}")).andExpect(status().isForbidden());
        assertEquals(0,endpoint.writes);
        mvc.perform(post("/json").contentType(MediaType.APPLICATION_JSON).content("{\"name\":null}")).andExpect(status().isOk());
        assertEquals(1,endpoint.writes);
    }
    @Test void aBinderDecisionCannotSurviveAChangedUserOrServiceViewAtTheMethodBoundary() throws Exception {
        user(); revokeFieldAtMethodBoundary=true;
        mvc.perform(post("/json").contentType(MediaType.APPLICATION_JSON).content("{\"name\":\"accepted-by-binder\"}"))
                .andExpect(status().isServiceUnavailable());
        assertEquals(0,endpoint.writes);
        revokeFieldAtMethodBoundary=false; changeServicePolicyAtMethodBoundary=true;
        service(Set.of(WRITE,"service:field:write"));
        mvc.perform(post("/json").contentType(MediaType.APPLICATION_JSON).content("{\"name\":\"accepted-by-binder\"}"))
                .andExpect(status().isServiceUnavailable());
        assertEquals(0,endpoint.writes);
    }

    @Test void readOnlyServiceCannotReadMultipartBytesOrWriteBusinessState() throws Exception {
        int[] reads={0};
        var file=new MockMultipartFile("file","x.txt","text/plain",new byte[]{1}){@Override public byte[] getBytes() throws java.io.IOException{reads[0]++;return super.getBytes();}};
        service(Set.of("service:object:read","service:field:write"));
        mvc.perform(multipart("/upload").file(file).param("name","x")).andExpect(status().isForbidden());
        assertEquals(0,reads[0]);assertEquals(0,endpoint.writes);
        service(Set.of(WRITE,"service:field:write"));
        mvc.perform(multipart("/upload").file(file).param("name","x")).andExpect(status().isOk());
        assertEquals(1,reads[0]);assertEquals(1,endpoint.writes);
    }
    private void user(){SecurityContextHolder.getContext().setAuthentication(new Rbac3AuthenticationToken(new Rbac3UserDetails(identity,userSnapshot()),List.of(new SimpleGrantedAuthority("SCOPE_user:write"))));}
    private void service(Set<String> scopes){SecurityContextHolder.getContext().setAuthentication(new IdpAuthenticationToken(new ServiceIdentityPrincipal("caller","20","caller","41",URI.create("https://api.example/shop"),0,scopes,"commerce","caller","test","credential",NOW.minusSeconds(1),NOW.plusSeconds(100)),List.of(),URI.create("https://idp.example/tenants/20")));}
    private RuntimePolicyBinding binding(){var d=new PermissionManifestCanonicalizer().digests(manifest);return new RuntimePolicyBinding("shop-java","1","a".repeat(64),d.policyDigest(),d.manifestDigest());}
    private Set<String> keys(){return manifest.resources().stream().map(PermissionManifest.ResourceDefinition::key).collect(java.util.stream.Collectors.toSet());}
    private SystemAuthorizationSnapshot userSnapshot(){var view=new EffectivePermissionSnapshot("https://idp.example/tenants/20","30",SCOPE,"1","2",Long.toString(policyVersion),new EffectivePermissionSnapshot.ActiveRoleContext("shop",List.of("50"),List.of("50")),codes.stream().sorted().toList(),NOW.plusSeconds(30));return new SystemAuthorizationSnapshot("20","30","60","shop",2,policyVersion,List.of("50"),null,null,codes,keys(),Map.of(),Map.of(),"sum",NOW,view.snapshotExpiresAt(),view,binding());}
    private PermissionManifest.ResourceDefinition api(String key,String path){return new PermissionManifest.ResourceDefinition("shop.api."+key,ResourceType.API,Map.of("methods",List.of("POST"),"paths",List.of(path)),ResourceAccess.PROTECTED,new PermissionRequirement(PermissionMode.ALL,List.of("order:write")),null,List.of(PermissionManifest.PrincipalType.USER,PermissionManifest.PrincipalType.SERVICE),List.of(WRITE),new PermissionManifest.I18nReference("shop",key),DefinitionLifecycle.ACTIVE);}
    private PermissionManifest.ResourceDefinition field(String name,ResourceAccess access,PermissionManifest.FieldPolicy policy){return new PermissionManifest.ResourceDefinition("shop.field."+name,ResourceType.FIELD,Map.of("dto",Input.class.getCanonicalName(),"property",name),access,null,policy,List.of(PermissionManifest.PrincipalType.USER,PermissionManifest.PrincipalType.SERVICE),List.of("service:field:write"),new PermissionManifest.I18nReference("shop",name),DefinitionLifecycle.ACTIVE);}
    @RestController static class Endpoint{
        private final PermissionExecutionGuard api;private final PermissionFieldBindingGuard fields;int writes;
        Endpoint(PermissionExecutionGuard api,PermissionFieldBindingGuard fields){this.api=api;this.fields=fields;}
        @PostMapping("/json") @PermissionResource(key="shop.api.json",type=ResourceType.API,labelPage="shop",labelKey="json",allowedPrincipals={PermissionManifest.PrincipalType.USER,PermissionManifest.PrincipalType.SERVICE},oauthScopes=WRITE)
        String json(@RequestBody Input input){api.requireExecution("shop.api.json");writes++;return "ok";}
        @PostMapping("/upload") @PermissionResource(key="shop.api.upload",type=ResourceType.API,labelPage="shop",labelKey="upload",allowedPrincipals={PermissionManifest.PrincipalType.USER,PermissionManifest.PrincipalType.SERVICE},oauthScopes=WRITE)
        String upload(@RequestParam String name,@RequestPart MultipartFile file)throws Exception{api.requireExecution("shop.api.upload");fields.require(Input.class,new SubmittedFieldSet(Set.of("name")),Set.of("name"));file.getBytes();writes++;return "ok";}
    }
}
