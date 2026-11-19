package top.egon.cola.platform.tianquan.jianshen.admin.config.runtime;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.boot.test.context.runner.WebApplicationContextRunner;
import top.egon.cola.component.tianshu.api.catalog.DdcLogicalCatalogContract;
import top.egon.cola.platform.tianquan.jianshen.admin.iam.business.converter.DdcLogicalCatalogViewConverter;
import top.egon.cola.platform.tianquan.jianshen.admin.iam.business.repository.DdcCatalogGateway;
import top.egon.cola.platform.tianquan.jianshen.admin.shared.tenant.domain.CatalogProjectionTenantContext;
import top.egon.cola.platform.tianquan.jianshen.core.rule.Rbac3RuleViolation;
import top.egon.cola.platform.tianquan.shoubing.contract.ServiceTokenContext;
import top.egon.cola.platform.tianquan.shoubing.starter.autoconfigure.IdpStarterProperties;
import top.egon.cola.platform.tianquan.shoubing.starter.client.IdpServiceOAuth2Client;
import top.egon.cola.platform.tianquan.shoubing.starter.client.IdpServiceOAuth2Client.IdpServiceAuthorizationException;
import top.egon.cola.platform.tianquan.shoubing.starter.client.IdpServiceTokenRequest;
import top.egon.cola.platform.tianquan.shoubing.starter.security.TrustedIssuerRegistry;

import java.net.URI;
import java.time.Duration;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

class Rbac3ApplicationConfigurationTest {

    private static final String PROFILE = "rbac3-catalog-command";
    private static final String PREFIX = "egon.tianquan-jianshen.logical-catalog.";
    private static final String AUDIENCE = "https://api.egon.internal/prod/platform/tianshu";
    private static final String ISSUER = "https://identity.egon.internal/tenant-7";

    private final IdpServiceOAuth2Client oauth = mock(IdpServiceOAuth2Client.class);
    private final TrustedIssuerRegistry issuers = mock(TrustedIssuerRegistry.class);
    private final Rbac3IdentityDirectoryTenantResolver tenantResolver = mock(Rbac3IdentityDirectoryTenantResolver.class);

    @Test
    void requestScopeSelectsTenantRegistrationAndFixedAudienceThroughTheActualSdk() {
        when(tenantResolver.authorizedJianshenTenant(null)).thenReturn("7");
        bindTokenFailure();
        enabled().withBean("idpRpcClientTenantResolver", Rbac3IdentityDirectoryTenantResolver.class, () -> tenantResolver)
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    assertThat(context).hasSingleBean(DdcCatalogGateway.class);
                    assertNoLegacyBeans(context);
                    assertReason(() -> catalog(context).listBusinesses("sample"), "DIRECTORY_RUNTIME_UNAVAILABLE");
                    assertTokenRequest("7", "jianshen-tenant-7");
                });
    }

    @Test
    void attestedProjectionUsesItsVerifiedScopeWithoutInheritingAmbientUserAuthorization() {
        bindTokenFailure();
        enabled().withBean("idpRpcClientTenantResolver", Rbac3IdentityDirectoryTenantResolver.class, () -> tenantResolver)
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    CatalogProjectionTenantContext.call("7", () -> {
                        assertReason(() -> catalog(context).listBusinesses("sample"), "DIRECTORY_RUNTIME_UNAVAILABLE");
                        return null;
                    });
                    assertTokenRequest("7", "jianshen-tenant-7");
                    verifyNoInteractions(tenantResolver);
                });
    }

    @Test
    void commandUsesOnlyExplicitCatalogTenantAndRefusesCrossTenantProjection() {
        bindTokenFailure();
        enabled().withPropertyValues("spring.profiles.active=" + PROFILE, PREFIX + "command-tenant=7")
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    assertNoLegacyBeans(context);
                    CatalogProjectionTenantContext.call("8", () -> {
                        assertReason(() -> catalog(context).listBusinesses("sample"), "PERMISSION_DENIED");
                        return null;
                    });
                    verify(oauth, never()).authorizeBounded(any(), anyString(), any(Duration.class));
                    assertReason(() -> catalog(context).listBusinesses("sample"), "DIRECTORY_RUNTIME_UNAVAILABLE");
                    assertTokenRequest("7", "jianshen-tenant-7");
                });
    }

    @Test
    void commandProfileCannotSupplyCredentialsToAServletApplication() {
        new WebApplicationContextRunner()
                .withUserConfiguration(Rbac3LogicalCatalogConfiguration.class)
                .withPropertyValues("spring.profiles.active=" + PROFILE, PREFIX + "enabled=true",
                        PREFIX + "command-tenant=7", PREFIX + "audience=" + AUDIENCE)
                .withBean("idpServiceOAuth2Client", IdpServiceOAuth2Client.class, () -> oauth)
                .withBean("jacksonObjectMapper", ObjectMapper.class, ObjectMapper::new)
                .run(context -> {
                    assertThat(context).hasFailed();
                    verify(oauth, never()).authorizeBounded(any(), anyString(), any(Duration.class));
                });
    }

    @Test
    void missingCommandScopeAndDisabledTransportNeverReportEmptyCatalog() {
        enabled().withPropertyValues("spring.profiles.active=" + PROFILE)
                .run(context -> assertThat(context).hasFailed());
        new ApplicationContextRunner().withUserConfiguration(Rbac3LogicalCatalogConfiguration.class)
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    assertReason(() -> catalog(context).listBusinesses("sample"), "DIRECTORY_RUNTIME_UNAVAILABLE");
                    verify(oauth, never()).authorizeBounded(any(), anyString(), any(Duration.class));
                });
    }

    private ApplicationContextRunner enabled() {
        IdpStarterProperties properties = new IdpStarterProperties();
        properties.getServiceClient().setAppId("tianquan-jianshen");
        properties.getServiceClient().setTenantRegistrationIds(Map.of("7", "jianshen-tenant-7"));
        when(issuers.activeIssuers()).thenReturn(List.of(new TrustedIssuerRegistry.TrustedIssuerVO(
                URI.create(ISSUER), URI.create(ISSUER + "/jwks"), "tenant-7",
                TrustedIssuerRegistry.RealmType.TENANT, "7", TrustedIssuerRegistry.Status.ACTIVE, 1)));
        return new ApplicationContextRunner()
                .withUserConfiguration(Rbac3LogicalCatalogConfiguration.class)
                .withPropertyValues(PREFIX + "enabled=true", PREFIX + "audience=" + AUDIENCE)
                .withBean("idpServiceOAuth2Client", IdpServiceOAuth2Client.class, () -> oauth)
                .withBean("idpStarterProperties", IdpStarterProperties.class, () -> properties)
                .withBean("trustedIssuerRegistry", TrustedIssuerRegistry.class, () -> issuers)
                .withBean("jacksonObjectMapper", ObjectMapper.class, ObjectMapper::new)
                .withBean("ddcLogicalCatalogViewConverterImpl", DdcLogicalCatalogViewConverter.class,
                        () -> mock(DdcLogicalCatalogViewConverter.class));
    }

    private void bindTokenFailure() {
        when(oauth.authorizeBounded(any(), anyString(), any(Duration.class)))
                .thenThrow(new IdpServiceAuthorizationException("fixture_unavailable", null));
    }

    private void assertTokenRequest(String tenant, String registration) {
        var issued = ArgumentCaptor.forClass(IdpServiceTokenRequest.class);
        verify(oauth).authorizeBounded(issued.capture(), eq(ISSUER), any(Duration.class));
        assertThat(issued.getValue().tenantId()).isEqualTo(tenant);
        assertThat(issued.getValue().registrationId()).isEqualTo(registration);
        assertThat(issued.getValue().audience()).isEqualTo(URI.create(AUDIENCE));
        assertThat(issued.getValue().context()).isEqualTo(ServiceTokenContext.TENANT);
        assertThat(issued.getValue().scopes()).containsExactly(DdcLogicalCatalogContract.SCOPE);
    }

    private static void assertNoLegacyBeans(org.springframework.context.ApplicationContext context) {
        assertThat(context.containsBean("ddcProviderLeaseStatusService")).isFalse();
        assertThat(context.containsBean("ddcRpcClientFactory")).isFalse();
        assertThat(context.containsBean("rpcDdcRegistrySnapshotLoader")).isFalse();
        assertThat(context.containsBean("ddcRedissonClient")).isFalse();
    }

    private static DdcCatalogGateway catalog(org.springframework.context.ApplicationContext context) {
        return context.getBean("ddcCatalogGateway", DdcCatalogGateway.class);
    }

    private static void assertReason(Runnable operation, String reason) {
        assertThatThrownBy(operation::run).isInstanceOfSatisfying(Rbac3RuleViolation.class,
                failure -> assertThat(failure.reasonCode()).isEqualTo(reason));
    }
}
