package top.egon.cola.platform.tianquan.jianshen.starter.autoconfigure;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.springframework.aop.framework.ProxyFactory;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.authorization.method.AuthorizationManagerBeforeMethodInterceptor;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.*;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.annotation.*;
import top.egon.cola.platform.tianquan.jianshen.starter.authorization.AuthorizationService;
import top.egon.cola.platform.tianquan.jianshen.starter.client.Rbac3AuthorizationClient;
import top.egon.cola.platform.tianquan.jianshen.starter.field.Rbac3FieldJacksonModule;
import top.egon.cola.platform.tianquan.jianshen.starter.permission.*;
import top.egon.cola.platform.tianquan.jianshen.starter.security.*;
import top.egon.cola.platform.tianquan.shoubing.starter.security.VerifiedUserTokenCarrier;
import java.util.*;
import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.mock;
import static top.egon.cola.platform.tianquan.jianshen.starter.permission.PermissionRuntimeFixture.*;

class Rbac3StarterAutoConfigurationTest {
    private static final PermissionManifest MANIFEST=manifest(List.of(new PermissionManifest.ResourceDefinition("shop.api.read",ResourceType.API,
            Map.of("methods",List.of("GET"),"paths",List.of("/orders")),ResourceAccess.PROTECTED,all("order:read"),null,
            List.of(PermissionManifest.PrincipalType.USER),List.of("api:orders:read"),new PermissionManifest.I18nReference("shop","read"),DefinitionLifecycle.ACTIVE)));
    private final ApplicationContextRunner runner=new ApplicationContextRunner().withConfiguration(AutoConfigurations.of(Rbac3StarterAutoConfiguration.class));
    private ApplicationContextRunner configured(boolean client){
        var value=runner.withPropertyValues("egon.cola.platform.tianquan.jianshen.enabled=true","egon.cola.platform.tianquan.jianshen.system-code=shop")
                .withBean(ObjectMapper.class,ObjectMapper::new).withBean("rbac3Clock",java.time.Clock.class,()->CLOCK)
                .withBean(PermissionPolicyRegistry.class,()->registry(MANIFEST))
                .withBean("defaultValidator",jakarta.validation.Validator.class,org.springframework.validation.beanvalidation.LocalValidatorFactoryBean::new);
        return client ? value.withBean(Rbac3AuthorizationClient.class,()->(system,user)->snapshot(MANIFEST,Set.of("order:read"))) : value;
    }
    @Test void staysDisabledByDefault(){runner.run(context->assertThat(context).doesNotHaveBean(AuthorizationService.class));}
    @Test void enabledHostWithoutTrustedBuildAndScopeFailsClosed(){
        runner.withPropertyValues("egon.cola.platform.tianquan.jianshen.enabled=true").withBean(ObjectMapper.class,ObjectMapper::new)
                .run(context->assertThat(context).hasFailed());
    }
    @Test void configuredAdvisorKeepsOAuthScopeAndPermissionExpressionIndependent(){
        try{
            var request=new MockHttpServletRequest();VerifiedUserTokenCarrier.set(request,"original-proof");
            RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request));
            configured(true).run(context->{
                assertThat(context).hasNotFailed();
                var advisor=context.getBean(AuthorizationManagerBeforeMethodInterceptor.class);
                var target=new ScopeFixture();var factory=new ProxyFactory(target);factory.addAdvisor(advisor);var proxy=(ScopeFixture)factory.getProxy();
                SecurityContextHolder.getContext().setAuthentication(new Rbac3AuthenticationToken(new Rbac3UserDetails(USER,snapshot(MANIFEST,Set.of("order:read")))));
                assertThatThrownBy(proxy::read).isInstanceOf(org.springframework.security.access.AccessDeniedException.class);assertThat(target.calls).isZero();
                SecurityContextHolder.getContext().setAuthentication(new Rbac3AuthenticationToken(new Rbac3UserDetails(USER,snapshot(MANIFEST,Set.of("order:read"))),List.of(new SimpleGrantedAuthority("SCOPE_api:orders:read"))));
                assertThat(proxy.read()).isEqualTo("original-result");assertThat(target.calls).isOne();
            });
        }finally{SecurityContextHolder.clearContext();RequestContextHolder.resetRequestAttributes();}
    }
    @Test void serviceTokenClientUsesTheQualifiedIdentityProperties(){
        configured(false).withPropertyValues("egon.cola.platform.tianquan.jianshen.authorization.service-token.enabled=true",
                        "egon.cola.platform.tianquan.jianshen.authorization.service-token.resource-uri=https://api.example/permission",
                        "egon.cola.platform.tianquan.jianshen.authorization.service-token.scopes=service:authorization:snapshot,service:authorization:policy",
                        "egon.cola.platform.tianquan.jianshen.authorization.endpoint=https://api.example/authorization")
                .withBean("idpServiceOAuth2Client",top.egon.cola.platform.tianquan.shoubing.starter.client.IdpServiceOAuth2Client.class,
                        ()->mock(top.egon.cola.platform.tianquan.shoubing.starter.client.IdpServiceOAuth2Client.class))
                .withBean("idpStarterProperties",top.egon.cola.platform.tianquan.shoubing.starter.autoconfigure.IdpStarterProperties.class,
                        top.egon.cola.platform.tianquan.shoubing.starter.autoconfigure.IdpStarterProperties::new)
                .withBean("anotherIdpProperties",top.egon.cola.platform.tianquan.shoubing.starter.autoconfigure.IdpStarterProperties.class,
                        top.egon.cola.platform.tianquan.shoubing.starter.autoconfigure.IdpStarterProperties::new)
                .run(context->assertThat(context).hasNotFailed().hasSingleBean(Rbac3AuthorizationClient.class));
    }
    @Test void consumerAuthorizationServiceRemainsAnExistingExtensionPoint(){
        var consumer=mock(AuthorizationService.class);
        configured(true).withBean(AuthorizationService.class,()->consumer).run(context->{
            assertThat(context).hasNotFailed();assertThat(context.getBean(AuthorizationService.class)).isSameAs(consumer);
            assertThat(context).hasSingleBean(AuthorizationManagerBeforeMethodInterceptor.class).hasSingleBean(top.egon.cola.platform.tianquan.jianshen.starter.field.PermissionJsonMapperFactory.class)
                    .doesNotHaveBean(Rbac3FieldJacksonModule.class);
        });
    }
    @Test void arbitraryBusinessKeysCannotBeAddedToTheControlPlaneBootstrapList(){
        assertThatThrownBy(()->new PermissionPolicyRegistry(MANIFEST,ARTIFACT,CLOCK,List.of(SCOPE),Set.of("shop.api.read")))
                .isInstanceOf(IllegalArgumentException.class);
    }
    public static class ScopeFixture{
        int calls;
        @PermissionResource(key="shop.api.read",type=ResourceType.API,labelPage="shop",labelKey="read",oauthScopes="api:orders:read")
        @RequiresPermissions(codes="order:read")
        public String read(){calls++;return "original-result";}
    }
}
