package top.egon.cola.platform.tianquan.jianshen.admin.config.runtime;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnNotWebApplication;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.context.SecurityContextHolder;
import top.egon.cola.component.tianshu.api.catalog.DdcLogicalCatalogClient;
import top.egon.cola.component.tianshu.api.catalog.DdcLogicalCatalogContract;
import top.egon.cola.component.tianshu.api.catalog.HttpDdcLogicalCatalogClient;
import top.egon.cola.component.tianshu.api.catalog.HttpDdcLogicalCatalogClient.AuthorizationVO;
import top.egon.cola.platform.tianquan.jianshen.admin.iam.business.converter.DdcLogicalCatalogViewConverter;
import top.egon.cola.platform.tianquan.jianshen.admin.iam.business.domain.vo.ApplicationCatalogEntry;
import top.egon.cola.platform.tianquan.jianshen.admin.iam.business.domain.vo.BusinessCatalogEntry;
import top.egon.cola.platform.tianquan.jianshen.admin.iam.business.repository.DdcCatalogGateway;
import top.egon.cola.platform.tianquan.jianshen.admin.iam.business.service.HttpDdcCatalogGateway;
import top.egon.cola.platform.tianquan.jianshen.admin.shared.tenant.domain.CatalogProjectionTenantContext;
import top.egon.cola.platform.tianquan.jianshen.admin.shared.tenant.domain.TenantContext;
import top.egon.cola.platform.tianquan.jianshen.core.rule.Rbac3RuleViolation;
import top.egon.cola.platform.tianquan.shoubing.contract.ServiceTokenContext;
import top.egon.cola.platform.tianquan.shoubing.starter.autoconfigure.IdpStarterProperties;
import top.egon.cola.platform.tianquan.shoubing.starter.client.IdpServiceOAuth2Client;
import top.egon.cola.platform.tianquan.shoubing.starter.client.IdpServiceTokenRequest;
import top.egon.cola.platform.tianquan.shoubing.starter.security.TrustedIssuerRegistry;

import java.net.URI;
import java.time.Duration;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.function.Supplier;

/** Binds the tenant-ranked logical directory to one approved Tianshu origin. */
@Configuration(value = "rbac3LogicalCatalogConfiguration", proxyBeanMethods = false)
@EnableConfigurationProperties(Rbac3LogicalCatalogConfiguration.CatalogProperties.class)
class Rbac3LogicalCatalogConfiguration {

    static final String PREFIX = "egon.tianquan-jianshen.logical-catalog";
    private static final String COMMAND_PROFILE = "rbac3-catalog-command";
    private static final String AUTHORIZATION_BEAN = "rbac3LogicalCatalogAuthorization";

    @Bean(AUTHORIZATION_BEAN)
    @Profile("!" + COMMAND_PROFILE)
    @ConditionalOnProperty(prefix = PREFIX, name = "enabled", havingValue = "true")
    Supplier<AuthorizationVO> requestCatalogAuthorization(
            CatalogProperties catalog,
            @Qualifier("idpStarterProperties") IdpStarterProperties idp,
            @Qualifier("trustedIssuerRegistry") TrustedIssuerRegistry issuers,
            @Qualifier("idpRpcClientTenantResolver") Rbac3IdentityDirectoryTenantResolver tenantResolver) {
        return () -> authorization(catalog, idp, issuers, requestTenant(tenantResolver));
    }

    @Bean(AUTHORIZATION_BEAN)
    @Profile(COMMAND_PROFILE)
    @ConditionalOnNotWebApplication
    @ConditionalOnProperty(prefix = PREFIX, name = "enabled", havingValue = "true")
    Supplier<AuthorizationVO> commandCatalogAuthorization(
            CatalogProperties catalog,
            @Qualifier("idpStarterProperties") IdpStarterProperties idp,
            @Qualifier("trustedIssuerRegistry") TrustedIssuerRegistry issuers) {
        String tenant = catalog.commandTenant();
        if (tenant == null || !tenant.matches("[1-9][0-9]{0,18}")) {
            throw new IllegalStateException("Catalog command requires a configured tenant");
        }
        authorization(catalog, idp, issuers, tenant);
        return () -> {
            requireTenantAgreement(tenant);
            return authorization(catalog, idp, issuers, tenant);
        };
    }

    @Bean(name = "ddcLogicalCatalogClient", destroyMethod = "close")
    @ConditionalOnProperty(prefix = PREFIX, name = "enabled", havingValue = "true")
    HttpDdcLogicalCatalogClient logicalCatalogClient(
            CatalogProperties properties,
            @Qualifier("idpServiceOAuth2Client") IdpServiceOAuth2Client oauth,
            @Qualifier(AUTHORIZATION_BEAN) Supplier<AuthorizationVO> authorization,
            @Qualifier("jacksonObjectMapper") ObjectMapper mapper) {
        return new HttpDdcLogicalCatalogClient(properties.origin(), oauth, authorization, mapper, properties.timeout());
    }

    @Bean("ddcCatalogGateway")
    @ConditionalOnProperty(prefix = PREFIX, name = "enabled", havingValue = "true")
    DdcCatalogGateway logicalCatalogGateway(
            @Qualifier("ddcLogicalCatalogClient") DdcLogicalCatalogClient client,
            @Qualifier("ddcLogicalCatalogViewConverterImpl") DdcLogicalCatalogViewConverter converter) {
        return new HttpDdcCatalogGateway(client, converter);
    }

    @Bean("ddcCatalogGateway")
    @ConditionalOnMissingBean(name = "ddcCatalogGateway")
    @ConditionalOnProperty(prefix = PREFIX, name = "enabled", havingValue = "false", matchIfMissing = true)
    DdcCatalogGateway unavailableDdcCatalogGateway() {
        return new DdcCatalogGateway() {
            @Override
            public Optional<BusinessCatalogEntry> findBusiness(String id) {
                throw unavailable();
            }

            @Override
            public List<BusinessCatalogEntry> listBusinesses(String keyword) {
                throw unavailable();
            }

            @Override
            public Optional<ApplicationCatalogEntry> findApplication(String id) {
                throw unavailable();
            }

            @Override
            public List<ApplicationCatalogEntry> listApplications(String id, String keyword) {
                throw unavailable();
            }

            private Rbac3RuleViolation unavailable() {
                return new Rbac3RuleViolation("DIRECTORY_RUNTIME_UNAVAILABLE");
            }
        };
    }

    private static String requestTenant(Rbac3IdentityDirectoryTenantResolver resolver) {
        String projectedTenant = CatalogProjectionTenantContext.currentOrNull();
        if (projectedTenant != null) {
            requireTenantAgreement(projectedTenant);
            return projectedTenant;
        }
        try {
            return resolver.authorizedJianshenTenant(SecurityContextHolder.getContext().getAuthentication());
        } catch (AccessDeniedException denied) {
            throw new Rbac3RuleViolation("PERMISSION_DENIED");
        }
    }

    private static void requireTenantAgreement(String tenant) {
        var incoming = TenantContext.currentOrNull();
        var projection = CatalogProjectionTenantContext.currentOrNull();
        if ((incoming != null && !tenant.equals(incoming.effectiveTenantId()))
                || (projection != null && !tenant.equals(projection))) {
            throw new Rbac3RuleViolation("PERMISSION_DENIED");
        }
    }

    private static AuthorizationVO authorization(
            CatalogProperties catalog, IdpStarterProperties idp, TrustedIssuerRegistry issuers, String tenant) {
        var client = idp.getServiceClient();
        String registration = client.getTenantRegistrationIds().get(tenant);
        var matchingIssuers = issuers.activeIssuers().stream()
                .filter(issuer -> issuer.realmType() == TrustedIssuerRegistry.RealmType.TENANT)
                .filter(issuer -> tenant.equals(issuer.tenantId()))
                .limit(2)
                .toList();
        String appId = client.getAppId();
        if (registration == null || registration.isBlank() || appId == null || appId.isBlank()
                || matchingIssuers.size() != 1) {
            throw new Rbac3RuleViolation("SERVICE_IDENTITY_DENIED");
        }
        var request = new IdpServiceTokenRequest(registration, appId, catalog.audience(),
                ServiceTokenContext.TENANT, tenant, Set.of(DdcLogicalCatalogContract.SCOPE));
        return new AuthorizationVO(request, matchingIssuers.getFirst().issuer().toASCIIString());
    }

    @ConfigurationProperties(prefix = PREFIX, ignoreUnknownFields = false)
    record CatalogProperties(boolean enabled,
            @DefaultValue("http://tianshu-admin-http.platform-prod.svc.cluster.local:18080") URI origin,
            URI audience, @DefaultValue("PT2S") Duration timeout, String commandTenant) {

        CatalogProperties {
            if (enabled && (audience == null || !"https".equals(audience.getScheme()) || audience.getHost() == null
                    || audience.getUserInfo() != null || audience.getQuery() != null || audience.getFragment() != null
                    || !audience.equals(audience.normalize()))) {
                throw new IllegalArgumentException("Logical catalog audience must be an exact HTTPS resource identifier");
            }
        }
    }
}
