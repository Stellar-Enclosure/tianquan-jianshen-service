package top.egon.cola.platform.tianquan.jianshen.admin.authorization.runtime;

import org.junit.jupiter.api.Test;
import org.springframework.boot.env.YamlPropertySourceLoader;
import org.springframework.core.env.PropertySource;
import org.springframework.core.io.FileSystemResource;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.runtime.domain.GatewayServiceKey;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.runtime.domain.vo.DdcProviderLeaseStatusVO;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.runtime.domain.vo.GatewayAdminSnapshotVO;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.runtime.domain.vo.GatewayConsistencyObservationVO;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.runtime.domain.vo.GatewayDefinitionStatusVO;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.runtime.domain.vo.GatewayProviderInstanceVO;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.runtime.domain.vo.GatewayProviderObservationVO;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.runtime.domain.vo.GatewayReleaseObservationVO;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.runtime.domain.vo.ServiceIdentityVO;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.runtime.repository.http.GatewayAdminControlPlaneStatusClient;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.runtime.service.GatewayDdcRuntimeStatusService;

import java.nio.file.Path;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class GatewayDdcConfigurationTest {

    private static final Instant NOW = Instant.parse("2026-07-30T12:00:00Z");
    private static final ServiceIdentityVO IDENTITY =
            new ServiceIdentityVO(
                    "tianquan-jianshen", "tianquan-jianshen-admin", "prod", "default",
                    "HTTP_PROVIDER", "http",
                    "tianquan-jianshen-admin", "default", "1.0.0");

    private static final String TIANSHU = "egon.cola.component.tianshu.";
    private static final String CATALOG = "egon.tianquan-jianshen.logical-catalog.";
    private static final String RPC = "egon.cola.component.rpc.";

    @Test
    void deploymentUsesAnExplicitStableHttpCatalogAndH2cBinding() throws Exception {
        PropertySource<?> base = yaml("application.yml").getFirst();
        PropertySource<?> local = yaml("application-local.yml").getFirst();

        assertThat(base.getProperty(CATALOG + "origin")).isEqualTo(
                "${TIANQUAN_JIANSHEN_LOGICAL_CATALOG_ORIGIN:http://tianshu-admin-http.platform-prod.svc.cluster.local:18080}");
        assertThat(local.getProperty(CATALOG + "origin")).isEqualTo(
                "${TIANQUAN_JIANSHEN_LOGICAL_CATALOG_ORIGIN:http://tianshu-admin-http.platform-local.svc.cluster.local:18080}");
        assertThat(local.getProperty(CATALOG + "enabled"))
                .isEqualTo("${TIANQUAN_JIANSHEN_LOGICAL_CATALOG_ENABLED:false}");
        assertThat(base.getProperty("egon.cola.component.id.machine-id")).isNull();
        assertThat(base.getProperty("spring.config.import[0]")).isNull();
        assertThat(base.getProperty(RPC + "transport")).isEqualTo("h2c");
        assertThat(base.getProperty(RPC + "provider.enabled")).isEqualTo(false);
        assertThat(base.getProperty(RPC + "consumer.bindings.shoubing-identity-directory.port"))
                .isEqualTo("${TIANQUAN_SHOUBING_RPC_SERVICE_PORT:18122}");
        assertThat(local.getProperty(RPC + "consumer.bindings.shoubing-identity-directory.namespace"))
                .isEqualTo("${TIANQUAN_SHOUBING_RPC_SERVICE_NAMESPACE:permission-local}");
        for (var source : List.of(base, local)) {
            assertThat(source.getProperty(TIANSHU + "rpc.target")).isNull();
            assertThat(source.getProperty(TIANSHU + "registry.http.enabled")).isNull();
            assertThat(source.getProperty("egon.cola.component.yuheng.openapi.publish-to-tianshu")).isNull();
            assertThat(source.getProperty(TIANSHU + "instance.lease-seconds")).isNull();
            assertThat(source.getProperty("spring.config.import")).isNull();
        }
    }

    @Test
    void adminClasspathContainsNoLegacyTransportEvenThroughOtherStarters() {
        ClassLoader loader = GatewayDdcConfigurationTest.class.getClassLoader();
        assertThat(loader.getResource(
                "top/egon/cola/component/tianshu/http/registration/DdcHttpRegistrationRuntime.class")).isNull();
        assertThat(loader.getResource(
                "top/egon/cola/component/rpc/tianshu/autoconfigure/DdcRpcAutoConfiguration.class")).isNull();
    }

    @Test
    void cloudNativeDeliveryRequiresExactlyTheMountedBaselineOutsideCommandProfiles() throws Exception {
        List<PropertySource<?>> docs = yaml("application.yml");
        assertThat(docs).hasSize(2);
        assertThat(docs.getFirst().getProperty(TIANSHU + "enabled")).isEqualTo(false);
        assertThat(docs.getFirst().getProperty(TIANSHU + "delivery.enabled")).isEqualTo(false);

        assertThat(docs.getFirst().getProperty("tianquan-jianshen.maximum-active-roots"))
                .isEqualTo("${egon.tianquan-jianshen.maximum-active-roots}");

        PropertySource<?> cloud = docs.getLast();
        assertThat(cloud.getProperty("spring.config.activate.on-profile"))
                .isEqualTo("cloud-native & !rbac3-catalog-command & !rbac3-platform-bootstrap");
        assertThat(cloud.getProperty("spring.config.import"))
                .isEqualTo("tianshu-baseline:/var/run/tianshu/config/baseline.json");
        assertThat(cloud.getProperty(TIANSHU + "delivery.enabled")).isEqualTo(true);
        assertThat(cloud.getProperty(TIANSHU + "baseline.scope.tenant-id"))
                .isEqualTo("${TIANSHU_CONFIG_TENANT_ID}");
        assertThat(cloud.getProperty(TIANSHU + "delivery.identity-tenant-id"))
                .isEqualTo("${TIANSHU_CONFIG_IDENTITY_TENANT_ID}");
        assertThat(cloud.getProperty(TIANSHU + "delivery.pod-uid"))
                .isEqualTo("${KUBERNETES_POD_UID}");
        assertThat(cloud.getProperty(TIANSHU + "baseline.target.binding-id"))
                .isEqualTo("${TIANSHU_CONFIG_BINDING_ID}");
    }

    @Test
    void routeabilityRequiresExactDefinitionLeaseProviderAndReleaseIdentity() {
        var definition = definition("definition-1");
        var lease = new AtomicReference<>(
                new DdcProviderLeaseStatusVO(
                        "REGISTERED", "instance-1", NOW.plusSeconds(30), IDENTITY));
        var client = mock(GatewayAdminControlPlaneStatusClient.class);
        when(client.snapshot()).thenReturn(snapshot("definition-1", "1.0.0", IDENTITY));
        var status = new GatewayDdcRuntimeStatusService(
                () -> definition, lease::get, client, IDENTITY,
                Clock.fixed(NOW, ZoneOffset.UTC));

        assertThat(status.status().gatewayRelease().status()).isEqualTo("ROUTABLE");

        when(client.snapshot()).thenReturn(snapshotWithReleaseStatus("ACTIVATING"));
        assertThat(status.status().gatewayRelease().status()).isEqualTo("NOT_ROUTABLE");

        when(client.snapshot()).thenReturn(snapshot("definition-1", "1.0.0", IDENTITY));
        lease.set(new DdcProviderLeaseStatusVO(
                "REGISTERED", "instance-1", NOW.minusSeconds(1), IDENTITY));
        assertThat(status.status().gatewayRelease().status()).isEqualTo("NOT_ROUTABLE");
        lease.set(new DdcProviderLeaseStatusVO(
                "REGISTERED", "instance-1", NOW.plusSeconds(30), IDENTITY));

        var wrongIdentity = new ServiceIdentityVO(
                "other-biz", "tianquan-jianshen-admin", "prod", "default",
                "HTTP_PROVIDER", "http",
                "tianquan-jianshen-admin", "default", "1.0.0");
        when(client.snapshot()).thenReturn(snapshot(
                "definition-1", "1.0.0", wrongIdentity));
        assertThat(status.status().gatewayRelease().status()).isEqualTo("NOT_ROUTABLE");

        when(client.snapshot()).thenReturn(GatewayAdminSnapshotVO.class.cast(new GatewayAdminSnapshotVO(
                        new GatewayReleaseObservationVO(
                                "UNKNOWN", "release-1", null, null, null,
                                "YUHENG_STATUS_UNAVAILABLE"),
                        new GatewayProviderObservationVO(
                                "UNKNOWN", List.of(), "YUHENG_STATUS_UNAVAILABLE"),
                        new GatewayConsistencyObservationVO(
                                "UNKNOWN", null, null, false, null,
                                "YUHENG_STATUS_UNAVAILABLE"), NOW)));
        assertThat(status.status().gatewayRelease().status()).isEqualTo("UNKNOWN");
    }

    private GatewayAdminSnapshotVO
    snapshotWithReleaseStatus(String releaseStatus) {
        GatewayAdminSnapshotVO routable =
                snapshot("definition-1", "1.0.0", IDENTITY);
        return new GatewayAdminSnapshotVO(
                new GatewayReleaseObservationVO(
                        "SUCCESS", "release-1", releaseStatus,
                        "definition-1", "1.0.0", null),
                routable.providers(), routable.consistency(), NOW);
    }

    private GatewayDefinitionStatusVO definition(String id) {
        return new GatewayDefinitionStatusVO(
                "ACCEPTED", id, List.of(), IDENTITY);
    }

    private GatewayAdminSnapshotVO snapshot(
            String definitionSetId,
            String publishedVersion,
            ServiceIdentityVO identity) {
        var key = new GatewayServiceKey(
                identity.bizCode(), identity.appCode(),
                identity.env(), identity.namespace(), identity.serviceKind(),
                identity.protocol(), identity.serviceName(), identity.group(),
                identity.version());
        return new GatewayAdminSnapshotVO(
                new GatewayReleaseObservationVO(
                        "SUCCESS", "release-1", "SUCCESS", definitionSetId,
                        publishedVersion, null),
                new GatewayProviderObservationVO(
                        "SUCCESS", List.of(new GatewayProviderInstanceVO("instance-1", "UP", key, definitionSetId)), null),
                new GatewayConsistencyObservationVO(
                        "SUCCESS", "release-1", "SUCCESS", true, "1", null), NOW);
    }

    private List<PropertySource<?>> yaml(String fileName) throws Exception {
        Path yaml = Path.of(System.getProperty("basedir"))
                .resolve("src/main/resources")
                .resolve(fileName);
        return new YamlPropertySourceLoader()
                .load(fileName, new FileSystemResource(yaml));
    }
}
