package top.egon.cola.platform.tianquan.jianshen.starter.permission;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.core.context.SecurityContextHolder;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.*;
import top.egon.cola.platform.tianquan.jianshen.starter.security.CurrentRbac3User;
import top.egon.cola.platform.tianquan.shoubing.starter.security.VerifiedUserTokenCarrier;
import java.util.List;
import java.util.Map;
import java.util.Set;
import static org.junit.jupiter.api.Assertions.*;
import static top.egon.cola.platform.tianquan.jianshen.starter.permission.PermissionRuntimeFixture.*;

class PermissionFieldCatalogTest {
    static class Input { public String name; @JsonProperty(access=JsonProperty.Access.READ_ONLY) public String calculated; public Nested nested; }
    static class Nested { public String detail; }
    static class ReadOnlyName { @JsonProperty(access=JsonProperty.Access.READ_ONLY) public String name; }
    static class ReadOnlyNested { @JsonProperty(access=JsonProperty.Access.READ_ONLY) public String detail; }
    static class InputRoute { public void input(@org.springframework.web.bind.annotation.RequestBody Input input) { } }
    static class Output { public String result; }
    private final String apiKey="shop.api.authorization.fields";
    private final PermissionManifest manifest=manifest(List.of(
            new PermissionManifest.ResourceDefinition(apiKey,ResourceType.API,Map.of("methods",List.of("GET"),"paths",List.of("/api/v1/authorization/field-catalog")),
                    ResourceAccess.PUBLIC,null,null,List.of(PermissionManifest.PrincipalType.USER),List.of(),new PermissionManifest.I18nReference("shop","fields"),DefinitionLifecycle.ACTIVE),
            field(Input.class,"name",ResourceAccess.PROTECTED,new PermissionManifest.FieldPolicy(PermissionManifest.JsonFieldType.STRING,
                    all("field:plain"),null,all("field:write"),null)),
            field(Input.class,"calculated",ResourceAccess.PUBLIC,null),field(Nested.class,"detail",ResourceAccess.PUBLIC,null),field(Output.class,"result",ResourceAccess.PUBLIC,null)));
    private final PermissionPolicyRegistry registry=registry(manifest);
    private final CurrentRbac3User users=new CurrentRbac3User();
    private final PermissionFieldCatalog catalog=new PermissionFieldCatalog(registry,new CurrentEffectivePermissionView(users,registry,CLOCK),users);
    private final ObjectMapper mapper=new ObjectMapper();
    @AfterEach void clear(){SecurityContextHolder.clearContext();}

    @Test void policyMetadataAndActualInputBindingAreIndependent() {
        authenticate(manifest,Set.of());
        var request=request("shop.field.Input.name","shop.field.Input.calculated","shop.field.Output.result");
        var view=catalog.current(request,apiKey,mapper,Set.of(Input.class));
        assertEquals(SCOPE,view.catalogScope());assertEquals("1",view.catalogVersion());
        assertTrue(view.fields().get("shop.field.Input.name").inputBinding());
        assertEquals(all("field:write"),view.fields().get("shop.field.Input.name").fieldPolicy().write());
        assertFalse(view.fields().get("shop.field.Input.calculated").inputBinding());
        assertFalse(view.fields().get("shop.field.Output.result").inputBinding());
        assertFalse(catalog.current(request,apiKey,mapper,Set.of()).fields().get("shop.field.Input.name").inputBinding());
    }

    @Test void callerCannotSelectAnotherScopeOrReadUnknownAndNonFieldKeys() {
        authenticate(manifest,Set.of());
        var request=request("shop.field.Input.name");request.addParameter("tenantId","21");
        assertThrows(IllegalArgumentException.class,()->catalog.current(request,apiKey,mapper,Set.of(Input.class)));
        for(String key:List.of("shop.field.missing",apiKey)) {
            assertThrows(IllegalArgumentException.class,()->catalog.current(request(key),apiKey,mapper,Set.of(Input.class)));
        }
        assertThrows(IllegalArgumentException.class,()->catalog.current(request("shop.field.Input.name","shop.field.Input.name"),apiKey,mapper,Set.of(Input.class)));
        var noProof=request("shop.field.Input.name");VerifiedUserTokenCarrier.clear(noProof);
        assertThrows(org.springframework.security.authentication.AuthenticationCredentialsNotFoundException.class,
                ()->catalog.current(noProof,apiKey,mapper,Set.of(Input.class)));
    }

    @Test void catalogAndEffectivePermissionViewUseTheSameAuthorityVersion() {
        authenticate(manifest,Set.of());
        var metadata=catalog.current(request("shop.field.Input.name"),apiKey,mapper,Set.of(Input.class));
        var current=new MockHttpServletRequest();VerifiedUserTokenCarrier.set(current,"verified-user");
        var view=new CurrentEffectivePermissionView(users,registry,CLOCK).current(current,apiKey);
        assertEquals(view.catalogScope(),metadata.catalogScope());assertEquals(view.catalogVersion(),metadata.catalogVersion());
    }

    @Test void firstReadableConverterOwnsRootAndNestedDtoMetadata() throws Exception {
        authenticate(manifest,Set.of());
        var strict=new ObjectMapper().addMixIn(Input.class,ReadOnlyName.class).addMixIn(Nested.class,ReadOnlyNested.class);
        var converter=new org.springframework.http.converter.json.MappingJackson2HttpMessageConverter(strict) {
            @Override public boolean canRead(Class<?> type,org.springframework.http.MediaType media){return type==Input.class&&super.canRead(type,media);}
            @Override public boolean canRead(java.lang.reflect.Type type,Class<?> context,org.springframework.http.MediaType media){return type==Input.class&&super.canRead(type,context,media);}
        };
        List<org.springframework.http.converter.HttpMessageConverter<?>> converters=List.of(converter,new org.springframework.http.converter.json.MappingJackson2HttpMessageConverter(mapper));
        var handlers=List.of(new org.springframework.web.method.HandlerMethod(new InputRoute(),InputRoute.class.getMethod("input",Input.class)));
        var result=catalog.currentForHttp(request("shop.field.Input.name","shop.field.Nested.detail","shop.field.Output.result"),apiKey,converters,handlers,
                Set.of("top.egon.cola.platform.tianquan.jianshen.starter.permission."),Set.of(Output.class));
        assertFalse(result.fields().get("shop.field.Input.name").inputBinding());
        assertFalse(result.fields().get("shop.field.Nested.detail").inputBinding());
        assertTrue(result.fields().get("shop.field.Output.result").inputBinding());
    }

    @Test void converterSpecificTypeMapperIsHonored() {
        authenticate(manifest,Set.of());
        var converter=new org.springframework.http.converter.json.MappingJackson2HttpMessageConverter(mapper);
        converter.registerObjectMappersForType(Input.class,mappers->mappers.put(org.springframework.http.MediaType.APPLICATION_JSON,
                new ObjectMapper().addMixIn(Input.class,ReadOnlyName.class)));
        List<org.springframework.http.converter.HttpMessageConverter<?>> converters=List.of(converter);
        List<org.springframework.web.method.HandlerMethod> handlers=List.of();
        assertFalse(catalog.currentForHttp(request("shop.field.Input.name"),apiKey,converters,handlers,
                Set.of("top.egon.cola.platform.tianquan.jianshen.starter.permission."),Set.of(Input.class))
                .fields().get("shop.field.Input.name").inputBinding());
    }

    private MockHttpServletRequest request(String...keys) {
        var request=new MockHttpServletRequest("GET","/api/v1/authorization/field-catalog");
        request.addParameter("keys",keys);VerifiedUserTokenCarrier.set(request,"verified-user");return request;
    }
}
