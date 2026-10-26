package top.egon.cola.platform.tianquan.jianshen.starter.field;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.context.SecurityContextHolder;
import top.egon.cola.component.common.desensitize.strategy.SensitiveStrategyRegistry;
import top.egon.cola.platform.tianquan.jianshen.contract.authorization.*;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.*;
import top.egon.cola.platform.tianquan.jianshen.starter.client.Rbac3AuthorizationClient;
import top.egon.cola.platform.tianquan.jianshen.starter.cache.SingleFlightSnapshotLoader;
import top.egon.cola.platform.tianquan.jianshen.starter.permission.*;
import top.egon.cola.platform.tianquan.jianshen.starter.security.CurrentRbac3User;
import top.egon.cola.platform.tianquan.shoubing.contract.*;
import top.egon.cola.platform.tianquan.shoubing.starter.security.IdpAuthenticationToken;
import java.net.URI;
import java.util.*;
import java.util.concurrent.atomic.AtomicReference;
import static org.junit.jupiter.api.Assertions.*;
import static top.egon.cola.platform.tianquan.jianshen.starter.permission.PermissionRuntimeFixture.*;

class ServiceFieldAuthorizationTest {
    public static class Input { public String name; @JsonProperty(access=JsonProperty.Access.READ_ONLY) public String calculated; }
    public static class Output { public String name="Ada"; }
    private final PermissionManifest manifest=manifest(List.of(api("read","GET","service:object:read"),api("write","POST","service:object:write"),
            field(Input.class,"name","service:field:write"),field(Input.class,"calculated","service:field:write"),
            field(Output.class,"name","service:field:read")));
    private final PermissionPolicyRegistry registry=registry(manifest);
    private final AtomicReference<ServicePolicySnapshot> policy=new AtomicReference<>(policy());
    private final Rbac3AuthorizationClient client=new Rbac3AuthorizationClient(){
        @Override public SystemAuthorizationSnapshot fetch(String system,IdentityPrincipal principal){throw new AssertionError("SERVICE cannot acquire a USER view");}
        @Override public ServicePolicySnapshot fetchPolicy(String system,ServiceIdentityPrincipal caller){return policy.get();}
    };
    private final PermissionServicePolicyGuard services=new PermissionServicePolicyGuard(registry,client,"shop",CLOCK);
    private final CurrentRbac3User users=new CurrentRbac3User();
    private final PermissionExecutionGuard api=new PermissionExecutionGuard(registry,users,new SingleFlightSnapshotLoader(client,"shop",CLOCK),services);
    private final PermissionFieldBindingGuard fields=new PermissionFieldBindingGuard(registry,users,services);
    private final ObjectMapper mapper=new ObjectMapper().registerModule(new Rbac3FieldJacksonModule(users,SensitiveStrategyRegistry.defaults(),registry,fields));
    @AfterEach void clear(){SecurityContextHolder.clearContext();}
    private PermissionManifest.ResourceDefinition api(String key,String method,String scope){
        return new PermissionManifest.ResourceDefinition("shop.api."+key,ResourceType.API,Map.of("methods",List.of(method),"paths",List.of("/"+key)),
                ResourceAccess.PROTECTED,null,null,List.of(PermissionManifest.PrincipalType.SERVICE),List.of(scope),
                new PermissionManifest.I18nReference("shop",key),DefinitionLifecycle.ACTIVE);
    }
    private PermissionManifest.ResourceDefinition field(Class<?> dto,String name,String scope){
        return new PermissionManifest.ResourceDefinition("shop.field."+dto.getSimpleName()+"."+name,ResourceType.FIELD,
                Map.of("dto",dto.getCanonicalName(),"property",name),ResourceAccess.PUBLIC,null,null,
                List.of(PermissionManifest.PrincipalType.USER,PermissionManifest.PrincipalType.SERVICE),List.of(scope),
                new PermissionManifest.I18nReference("shop",name),DefinitionLifecycle.ACTIVE);
    }
    private ServicePolicySnapshot policy(){
        var digests=new PermissionManifestCanonicalizer().digests(manifest);
        return new ServicePolicySnapshot(SCOPE,"1","3",new RuntimePolicyBinding("shop-java","1",ARTIFACT,digests.policyDigest(),digests.manifestDigest()),
                manifest.resources().stream().map(PermissionManifest.ResourceDefinition::key).collect(java.util.stream.Collectors.toSet()),NOW.plusSeconds(30));
    }
    private void service(Set<String> scopes){
        var principal=new ServiceIdentityPrincipal("caller","20","caller","41",URI.create("https://api.example/shop"),0,scopes,
                "commerce","caller","test","credential",NOW.minusSeconds(10),NOW.plusSeconds(60));
        SecurityContextHolder.getContext().setAuthentication(new IdpAuthenticationToken(principal,List.of(),URI.create("https://idp.example/tenants/20")));
    }
    @Test void serviceReadUsesPolicyWithoutSynthesizingUserPermissions(){
        service(Set.of("service:object:read","service:field:read"));
        var result=new PermissionOutputProjection(api,mapper).project("shop.api.read",new Output());
        assertEquals("Ada",result.path("name").asText()); assertTrue(users.current().isEmpty());
    }
    @Test void readOnlyServiceCannotEnterTheRpcWriteCommand(){
        service(Set.of("service:object:read","service:field:write"));
        int[] writes={0};
        assertThrows(org.springframework.security.authorization.AuthorizationDeniedException.class,()->{
            try(var scope=api.open("shop.api.write")){fields.require(Input.class,new SubmittedFieldSet(Set.of("name")),Set.of("name"));writes[0]++;}
        });
        assertEquals(0,writes[0]);
    }
    @Test void readApiCannotBeReusedAsAWriteAdapterEvenWithFieldWriteScope(){
        service(Set.of("service:object:read","service:field:write"));
        try(var scope=api.open("shop.api.read")){
            assertThrows(org.springframework.security.authorization.AuthorizationDeniedException.class,
                    ()->fields.require(Input.class,new SubmittedFieldSet(Set.of("name")),Set.of("name")));
        }
        assertThrows(org.springframework.security.authorization.AuthorizationDeniedException.class,PermissionExecutionContext::currentApiKey);
    }
    @Test void serviceJsonInputStillHonorsNullAndActualReadOnlyBindings() throws Exception {
        service(Set.of("service:object:write","service:field:write"));
        try(var scope=api.open("shop.api.write")){
            assertNull(mapper.readValue("{\"name\":null}",Input.class).name);
            assertThrows(Exception.class,()->mapper.readValue("{\"calculated\":\"bad\"}",Input.class));
            assertThrows(org.springframework.security.authorization.AuthorizationDeniedException.class,
                    ()->fields.require(Input.class,new SubmittedFieldSet(Set.of("calculated")),Set.of("calculated")));
        }
    }
    @Test void expiredOrChangedPolicyCannotUseAFormerServiceView(){
        service(Set.of("service:object:read","service:field:read"));
        var first=policy.get();
        policy.set(new ServicePolicySnapshot(SCOPE,"1","3",first.policyBinding(),first.resourceKeys(),NOW.minusSeconds(1)));
        assertThrows(org.springframework.security.authorization.AuthorizationDeniedException.class,()->api.requireExecution("shop.api.read"));
        policy.set(new ServicePolicySnapshot(SCOPE,"2","4",new RuntimePolicyBinding("shop-java","2",ARTIFACT,"f".repeat(64),"e".repeat(64)),first.resourceKeys(),NOW.plusSeconds(30)));
        assertThrows(org.springframework.security.authorization.AuthorizationDeniedException.class,()->api.requireExecution("shop.api.read"));
    }
}
