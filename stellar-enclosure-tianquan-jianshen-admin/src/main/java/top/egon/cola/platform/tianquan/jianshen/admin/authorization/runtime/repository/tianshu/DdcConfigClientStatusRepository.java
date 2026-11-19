package top.egon.cola.platform.tianquan.jianshen.admin.authorization.runtime.repository.tianshu;

import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.lang.Nullable;
import top.egon.cola.component.tianshu.service.config.DdcConfigSnapshotCoordinator;
import top.egon.cola.component.tianshu.state.DdcLocalConfigState;
import top.egon.cola.component.tianshu.state.DdcLocalConfigState.DeliveryObservationVO;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.runtime.domain.vo.ApplyFailureVO;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.runtime.domain.vo.DdcConfigClientStatusVO;

/** Projects native configuration evidence without fabricating a registration or lease. */
@Slf4j
@RequiredArgsConstructor(onConstructor_ = @Autowired)
public final class DdcConfigClientStatusRepository {

    @NonNull
    @Qualifier("ddcLocalConfigState")
    private final ObjectProvider<DdcLocalConfigState> observations;
    @NonNull
    @Qualifier("ddcConfigSnapshotCoordinator")
    private final ObjectProvider<DdcConfigSnapshotCoordinator> coordinator;
    @NonNull
    @Qualifier("rbac3RuntimePolicy")
    private final AtomicRbac3RuntimePolicy policy;

    public DdcConfigClientStatusVO status() {
        DeliveryObservationVO observation = observationOrNull();
        String state = observation == null ? "UNKNOWN" : observation.status().name();
        if (observation != null && observation.ready() && !nativeReady(observation)) {
            state = "STALE";
        }
        ApplyFailureVO failure = policy.lastApplyFailure().orElse(null);
        return new DdcConfigClientStatusVO(state, null, null, null,
                policy.current().configVersions(), failure == null ? null : failure.key(),
                failure == null ? null : failure.targetVersion(), failure == null ? null : failure.errorCode());
    }

    public boolean ready() {
        DeliveryObservationVO observation = observationOrNull();
        return observation != null && nativeReady(observation);
    }

    @Nullable
    private DeliveryObservationVO observationOrNull() {
        try {
            DdcLocalConfigState local = observations.getIfAvailable();
            return local == null ? null : local.deliveryObservation();
        } catch (RuntimeException unavailable) {
            log.debug("Native config observation unavailable failureType={}", unavailable.getClass().getSimpleName());
            return null;
        }
    }

    private boolean nativeReady(DeliveryObservationVO observation) {
        if (!observation.ready()) {
            return false;
        }
        try {
            DdcConfigSnapshotCoordinator runtime = coordinator.getIfAvailable();
            return runtime != null && runtime.ready();
        } catch (RuntimeException unavailable) {
            return false;
        }
    }
}
