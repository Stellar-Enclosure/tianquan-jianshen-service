package top.egon.cola.platform.tianquan.jianshen.admin.config.runtime;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.support.StaticListableBeanFactory;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.runtime.domain.vo.DefinitionStatusVO;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.runtime.domain.vo.FenceMutationStatusVO;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.runtime.domain.vo.FlywayStatusVO;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.runtime.domain.vo.OperationalStatusVO;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.runtime.domain.vo.OutboxStatusVO;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.runtime.domain.vo.ProviderLeaseStatusVO;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.runtime.domain.vo.RedisProjectionStatusVO;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.runtime.domain.vo.RuntimeStatusVO;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.runtime.repository.tianshu.DdcConfigClientStatusRepository;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.runtime.repository.http.GatewayDefinitionStatusRepository;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.runtime.service.Rbac3OperationalRuntimeStatusService;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class Rbac3IndependentProviderStatusTest {

    private static final Instant NOW = Instant.parse("2026-09-06T03:00:00Z");

    @Test
    void keepsRetiredLeaseAndUnobservedRouteDistinctFromLocalRuntimeHealth() {
        RuntimeStatusVO status = status(new StaticListableBeanFactory());

        assertThat(status.providerLease()).isEqualTo(new ProviderLeaseStatusVO("STOPPED", null, null));
        assertThat(status.definition()).isEqualTo(new DefinitionStatusVO(
                "UNKNOWN", null, List.of("CONTROL_PLANE_DISABLED")));
        assertThat(status.gatewayRelease().status()).isEqualTo("UNKNOWN");
        assertThat(status.flyway()).isEqualTo(new FlywayStatusVO("UP_TO_DATE", "UP_TO_DATE"));
        assertThat(status.checkedAt()).isEqualTo(NOW);

        JsonNode provider = new ObjectMapper().valueToTree(status.providerLease());
        assertThat(provider.required("state").asText()).isEqualTo("STOPPED");
        assertThat(provider.required("instanceId").isNull()).isTrue();
        assertThat(provider.required("leaseExpireAt").isNull()).isTrue();
    }

    private RuntimeStatusVO status(StaticListableBeanFactory beans) {
        Rbac3OperationalRuntimeStatusService operational = mock(Rbac3OperationalRuntimeStatusService.class);
        when(operational.status()).thenReturn(new OperationalStatusVO(
                new FlywayStatusVO("UP_TO_DATE", "UP_TO_DATE"),
                new RedisProjectionStatusVO("HEALTHY", 0),
                new FenceMutationStatusVO("HEALTHY", 0, 0, 0),
                new OutboxStatusVO("HEALTHY", 0, 0)));
        return new Rbac3PlatformIntegrationConfiguration().rbac3ControlPlaneRuntimeStatusPort(
                beans.getBeanProvider(GatewayDefinitionStatusRepository.class),
                beans.getBeanProvider(DdcConfigClientStatusRepository.class),
                operational, Clock.fixed(NOW, ZoneOffset.UTC)).status();
    }
}
