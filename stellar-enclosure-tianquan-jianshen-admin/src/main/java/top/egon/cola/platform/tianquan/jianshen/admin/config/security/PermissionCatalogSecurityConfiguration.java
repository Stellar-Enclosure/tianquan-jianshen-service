package top.egon.cola.platform.tianquan.jianshen.admin.config.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AnonymousAuthenticationFilter;
import org.springframework.security.web.context.NullSecurityContextRepository;
import org.springframework.security.web.savedrequest.NullRequestCache;
import top.egon.cola.platform.tianquan.shoubing.contract.ServiceIdentityPrincipal;
import top.egon.cola.platform.tianquan.shoubing.starter.security.IdpBearerAuthenticationFilter;
import top.egon.cola.platform.tianquan.shoubing.starter.security.IdpSecurityObservationFilter;

/** Catalog machine operations authenticate before the user authorization Runtime exists. */
@Configuration(proxyBeanMethods = false)
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
public class PermissionCatalogSecurityConfiguration {

    @Bean
    @Order(-1)
    SecurityFilterChain permissionCatalogSharedChain(HttpSecurity http,
            @Qualifier("idpBearerAuthenticationFilter") IdpBearerAuthenticationFilter authentication,
            @Qualifier("rbac3BearerAuthenticationFilter") top.egon.cola.platform.tianquan.jianshen.starter.security.Rbac3BearerAuthenticationFilter authorization,
            @Qualifier("idpSecurityObservationFilter") ObjectProvider<IdpSecurityObservationFilter> observations,
            @Qualifier("jacksonObjectMapper") ObjectMapper mapper) throws Exception {
        http.securityMatcher("/api/v1/permission-catalogs/activations", "/api/v1/permission-catalogs/versions")
                .csrf(csrf -> csrf.disable())
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .securityContext(context -> context.securityContextRepository(new NullSecurityContextRepository()))
                .requestCache(cache -> cache.requestCache(new NullRequestCache()))
                .authorizeHttpRequests(authorize -> authorize.anyRequest().access((supplier, context) -> {
                    var value = supplier.get();
                    return new org.springframework.security.authorization.AuthorizationDecision(value != null && value.isAuthenticated()
                            && (value.getPrincipal() instanceof ServiceIdentityPrincipal
                            || value.getPrincipal() instanceof top.egon.cola.platform.tianquan.jianshen.starter.security.Rbac3UserDetails));
                }))
                .addFilterBefore(authentication, AnonymousAuthenticationFilter.class)
                .addFilterAfter(authorization, IdpBearerAuthenticationFilter.class)
                .exceptionHandling(exceptions -> exceptions.authenticationEntryPoint((request, response, failure) ->
                        Rbac3AdminSecurityConfiguration.authenticationFailure(request, response, mapper))
                        .accessDeniedHandler((request, response, failure) -> Rbac3AdminSecurityConfiguration.authorizationFailure(request, response, mapper)));
        IdpSecurityObservationFilter observation = observations.getIfAvailable();
        if (observation != null) http.addFilterBefore(observation, IdpBearerAuthenticationFilter.class);
        return http.build();
    }

    @Bean
    @Order(0)
    SecurityFilterChain permissionCatalogMachineChain(HttpSecurity http,
            @Qualifier("idpBearerAuthenticationFilter") IdpBearerAuthenticationFilter authentication,
            @Qualifier("idpSecurityObservationFilter") ObjectProvider<IdpSecurityObservationFilter> observations,
            @Qualifier("jacksonObjectMapper") ObjectMapper mapper) throws Exception {
        http.securityMatcher("/api/v1/permission-manifests/**",
                        "/internal/v1/permission-catalogs/**")
                .csrf(csrf -> csrf.disable())
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .securityContext(context -> context.securityContextRepository(new NullSecurityContextRepository()))
                .requestCache(cache -> cache.requestCache(new NullRequestCache()))
                .authorizeHttpRequests(authorize -> authorize.anyRequest().access((supplier, context) -> {
                    var value = supplier.get();
                    return new org.springframework.security.authorization.AuthorizationDecision(value != null && value.isAuthenticated()
                            && value.getPrincipal() instanceof ServiceIdentityPrincipal);
                }))
                .addFilterBefore(authentication, AnonymousAuthenticationFilter.class)
                .exceptionHandling(exceptions -> exceptions.authenticationEntryPoint((request, response, failure) ->
                        Rbac3AdminSecurityConfiguration.authenticationFailure(request, response, mapper))
                        .accessDeniedHandler((request, response, failure) ->
                                Rbac3AdminSecurityConfiguration.authorizationFailure(request, response, mapper)));
        IdpSecurityObservationFilter observation = observations.getIfAvailable();
        if (observation != null) http.addFilterBefore(observation, IdpBearerAuthenticationFilter.class);
        return http.build();
    }
}
