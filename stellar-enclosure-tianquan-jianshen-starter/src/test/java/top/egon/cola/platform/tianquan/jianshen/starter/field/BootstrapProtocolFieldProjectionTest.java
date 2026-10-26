package top.egon.cola.platform.tianquan.jianshen.starter.field;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.context.SecurityContextHolder;
import top.egon.cola.component.common.desensitize.strategy.SensitiveStrategyRegistry;
import top.egon.cola.platform.tianquan.jianshen.admin.registration.catalog.service.PermissionManifestPlanService.Result;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.*;
import top.egon.cola.platform.tianquan.jianshen.starter.permission.*;
import top.egon.cola.platform.tianquan.jianshen.starter.security.*;
import top.egon.cola.platform.tianquan.jianshen.starter.client.Rbac3AuthorizationClient;
import top.egon.cola.platform.tianquan.shoubing.contract.*;
import top.egon.cola.platform.tianquan.shoubing.starter.security.IdpAuthenticationToken;
import java.net.URI;
import java.time.*;
import java.util.*;
import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;

class BootstrapProtocolFieldProjectionTest {
    private static final Instant NOW=Instant.parse("2026-10-25T00:00:00Z");
    private static final String PLAN="tianquan-jianshen.api.manifest.plan", SCOPE="tianquan-jianshen:permission-manifest:register";
    @AfterEach void clear(){SecurityContextHolder.clearContext();}
    @Test void firstServicePlanResponseIsReadWithoutAnActiveSnapshotButNeverGrantsInput()throws Exception {
        var fixture=new Fixture(SCOPE,Result.class);fixture.service("20",true,Set.of(SCOPE));
        try(var boundary=fixture.execution.open(PLAN)) {
            assertThat(fixture.mapper.readTree(fixture.mapper.writeValueAsString(new Result("plan-1"))).path("planId").asText()).isEqualTo("plan-1");
            verifyNoInteractions(fixture.policies);
            assertThatThrownBy(()->fixture.fields.require(Result.class,new SubmittedFieldSet(Set.of("planId")),Set.of("planId")))
                    .isInstanceOf(Rbac3AuthorizationClient.AuthorizationUnavailableException.class);
        }
    }
    @Test void arbitraryDtoFieldScopeForeignTenantAndUnverifiedServiceHaveNoExemption()throws Exception {
        var foreign=new Fixture(SCOPE,Business.class);foreign.service("20",true,Set.of(SCOPE));
        try(var boundary=foreign.execution.open(PLAN)) {assertThatThrownBy(()->foreign.mapper.writeValueAsString(new Business("data"))).hasRootCauseMessage("BOOTSTRAP_RESPONSE_FIELD_DENIED");}
        var wrongScope=new Fixture("other:scope",Result.class);wrongScope.service("20",true,Set.of(SCOPE,"other:scope"));
        try(var boundary=wrongScope.execution.open(PLAN)) {assertThatThrownBy(()->wrongScope.mapper.writeValueAsString(new Result("plan-1"))).hasRootCauseMessage("BOOTSTRAP_RESPONSE_FIELD_DENIED");}
        var fixture=new Fixture(SCOPE,Result.class);fixture.service("21",true,Set.of(SCOPE));
        assertThatThrownBy(()->fixture.execution.open(PLAN)).hasMessage("BOOTSTRAP_SERVICE_BINDING_MISMATCH");
        fixture.service("20",false,Set.of(SCOPE));assertThatThrownBy(()->fixture.execution.open(PLAN)).hasMessage("VERIFIED_SERVICE_IDENTITY_REQUIRED");
    }
    @Test void userProjectionStillNeedsItsActiveCatalogEvenForAnApprovedProtocolDto()throws Exception {
        var fixture=new Fixture(SCOPE,Result.class);
        var identity=new IdentityPrincipal("user","20","42",Set.of("https://api.example/r"),NOW.minusSeconds(1),NOW.plusSeconds(100),AuthenticationContext.password());
        var legacy=new top.egon.cola.platform.tianquan.jianshen.contract.authorization.SystemAuthorizationSnapshot("20","user","60","tianquan-jianshen",1,1,List.of(),null,null,Set.of(),Set.of("tianquan-jianshen.field.result.planId"),Map.of(),Map.of(),"legacy",NOW,NOW.plusSeconds(30));
        SecurityContextHolder.getContext().setAuthentication(new Rbac3AuthenticationToken(new Rbac3UserDetails(identity,legacy)));
        assertThatThrownBy(()->fixture.mapper.writeValueAsString(new Result("plan-1"))).hasRootCauseMessage("AUTH_DEPLOYMENT_BINDING_MISMATCH");
    }

    @Test void aRegularApiStillRequiresTheCurrentServicePolicy()throws Exception {
        var fixture=new Fixture(SCOPE,Result.class);fixture.service("20",true,Set.of(SCOPE));
        assertThatThrownBy(()->fixture.execution.open("tianquan-jianshen.api.regular"))
                .isInstanceOf(Rbac3AuthorizationClient.AuthorizationUnavailableException.class);
    }
    @Test void everyApprovedProtocolIdentityIsExactRatherThanAPackageOrClassPrefix() {
        var approved=Map.of(
                "tianquan-jianshen.api.manifest.plan","top.egon.cola.platform.tianquan.jianshen.admin.registration.catalog.service.PermissionManifestPlanService.Result",
                "tianquan-jianshen.api.manifest.register","top.egon.cola.platform.tianquan.jianshen.admin.registration.catalog.service.PermissionManifestRegistrationService.Result",
                "tianquan-jianshen.api.manifest.status","top.egon.cola.platform.tianquan.jianshen.admin.registration.catalog.service.PermissionManifestRegistrationService.Result",
                "tianquan-jianshen.api.catalog.qualify","top.egon.cola.platform.tianquan.jianshen.admin.registration.catalog.domain.vo.DeploymentQualificationReceiptVO",
                "tianquan-jianshen.api.catalog.versions","top.egon.cola.platform.tianquan.jianshen.admin.registration.catalog.repository.PermissionCatalogActivationRepository.History");
        var apis=approved.keySet().stream().map(Fixture::api).toList();
        var manifest=new PermissionManifest("1.0",new PermissionManifest.Application("xingyuan","tianquan-jianshen"),new PermissionManifest.Producer("r-java",PermissionManifest.ProducerKind.JAVA,PermissionManifest.SnapshotMode.FULL,List.of("tianquan-jianshen."),List.of("r"),List.of("r"),false),new PermissionManifest.Artifact("r","a".repeat(40),"b","1"),List.of(),List.of(),apis,List.of(),List.of());
        var registry=new PermissionPolicyRegistry(manifest,"a".repeat(64),Clock.fixed(NOW,ZoneOffset.UTC),List.of(new CatalogScope("10","20","xingyuan","tianquan-jianshen","default","test")),approved.keySet());
        approved.forEach((api,dto)->{
            for(String candidate:List.of(dto,dto+"Extra",dto+".Nested")) {
                var field=new PermissionManifest.ResourceDefinition("tianquan-jianshen.field.protocol.value",ResourceType.FIELD,Map.of("dto",candidate,"property","value"),ResourceAccess.PUBLIC,null,null,List.of(PermissionManifest.PrincipalType.SERVICE),List.of(SCOPE),new PermissionManifest.I18nReference("runtime","value"),DefinitionLifecycle.ACTIVE);
                assertThat(registry.bootstrapResponseField(api,field)).as(api+" / "+candidate).isEqualTo(candidate.equals(dto));
            }
        });
    }

    public record Business(String planId) { }
    static class Fixture {
        final PermissionServicePolicyGuard policies=mock(PermissionServicePolicyGuard.class);
        final PermissionExecutionGuard execution;final PermissionFieldBindingGuard fields;final ObjectMapper mapper;
        Fixture(String fieldScope,Class<?> dto) {
            var resources=List.of(api(PLAN),api("tianquan-jianshen.api.regular"),new PermissionManifest.ResourceDefinition("tianquan-jianshen.field.result.planId",ResourceType.FIELD,
                    Map.of("dto",dto.getCanonicalName(),"property","planId"),ResourceAccess.PUBLIC,null,null,List.of(PermissionManifest.PrincipalType.USER,PermissionManifest.PrincipalType.SERVICE),List.of(fieldScope),new PermissionManifest.I18nReference("runtime","result"),DefinitionLifecycle.ACTIVE));
            var manifest=new PermissionManifest("1.0",new PermissionManifest.Application("xingyuan","tianquan-jianshen"),new PermissionManifest.Producer("r-java",PermissionManifest.ProducerKind.JAVA,PermissionManifest.SnapshotMode.FULL,List.of("tianquan-jianshen."),List.of("r"),List.of("r"),false),new PermissionManifest.Artifact("r","a".repeat(40),"b","1"),List.of(),List.of(),resources,List.of(),List.of());
            var registry=new PermissionPolicyRegistry(manifest,"a".repeat(64),Clock.fixed(NOW,ZoneOffset.UTC),List.of(new CatalogScope("10","20","xingyuan","tianquan-jianshen","default","test")),Set.of(PLAN));
            var users=new CurrentRbac3User();fields=new PermissionFieldBindingGuard(registry,users,policies);execution=new PermissionExecutionGuard(registry,users,null,policies);
            mapper=new PermissionJsonMapperFactory(users,SensitiveStrategyRegistry.defaults(),registry,fields).forTransport(new ObjectMapper());
            when(policies.require(any(),anyString())).thenThrow(new Rbac3AuthorizationClient.AuthorizationUnavailableException("SQL_CATALOG_NOT_ACTIVE"));
        }
        void service(String tenant,boolean verified,Set<String> scopes) {
            var service=new ServiceIdentityPrincipal("caller",tenant,"caller","41",URI.create("https://api.example/r"),0,scopes,"xingyuan","ci","test","credential",NOW.minusSeconds(1),NOW.plusSeconds(100));
            SecurityContextHolder.getContext().setAuthentication(new IdpAuthenticationToken(service,List.of(),verified?URI.create("https://idp.example/tenants/"+tenant):null));
        }
        private static PermissionManifest.ResourceDefinition api(String key){return new PermissionManifest.ResourceDefinition(key,ResourceType.API,Map.of("methods",List.of("POST"),"paths",List.of("/plan")),ResourceAccess.PROTECTED,null,null,List.of(PermissionManifest.PrincipalType.SERVICE),List.of(SCOPE),new PermissionManifest.I18nReference("runtime","plan"),DefinitionLifecycle.ACTIVE);}
    }
}
