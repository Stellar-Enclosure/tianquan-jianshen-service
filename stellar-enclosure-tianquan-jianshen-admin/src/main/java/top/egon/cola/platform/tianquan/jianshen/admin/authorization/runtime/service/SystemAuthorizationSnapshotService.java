package top.egon.cola.platform.tianquan.jianshen.admin.authorization.runtime.service;

import top.egon.cola.platform.tianquan.jianshen.admin.authorization.runtime.decision.domain.vo.SnapshotRecordVO;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.runtime.decision.repository.AuthorizationSnapshotRepository;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.runtime.repository.InitialAuthorizationContextRepository;
import top.egon.cola.platform.tianquan.jianshen.contract.authorization.AppAuthorizationContext;
import top.egon.cola.platform.tianquan.jianshen.contract.authorization.SystemAuthorizationSnapshot;
import top.egon.cola.platform.tianquan.jianshen.core.rule.Rbac3RuleViolation;

import java.time.Clock;
import java.time.Instant;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

/**
 * Projects one user snapshot into a system-specific authorization view.
 */
public final class SystemAuthorizationSnapshotService {

    private final AuthorizationSnapshotRepository snapshots;
    private final Clock clock;

    public SystemAuthorizationSnapshotService(
            AuthorizationSnapshotRepository snapshots,
            Clock clock) {
        this(snapshots, (tenantId, identitySub) -> Optional.empty(), clock);
    }

    public SystemAuthorizationSnapshotService(
            AuthorizationSnapshotRepository snapshots,
            InitialAuthorizationContextRepository initialContexts,
            Clock clock) {
        this(snapshots, initialContexts, clock, false);
    }

    /**
     * Retains the legacy constructor signature without deriving permissions from an initial context.
     * Runtime authority always requires a published snapshot backed by explicit grants.
     */
    public SystemAuthorizationSnapshotService(
            AuthorizationSnapshotRepository snapshots,
            InitialAuthorizationContextRepository initialContexts,
            Clock clock,
            boolean ddcInitialContextEnabled) {
        this.snapshots = Objects.requireNonNull(snapshots, "snapshots");
        this.clock = Objects.requireNonNull(clock, "clock");
    }

    public SystemAuthorizationSnapshot snapshot(
            String tenantId,
            String identitySub,
            String systemCode) {
        SnapshotRecordVO record = snapshots.load(tenantId, identitySub);
        if (!identitySub.equals(record.identitySub())) {
            throw new Rbac3RuleViolation("IDENTITY_SUBJECT_MISMATCH");
        }
        var user = record.snapshot();
        AppAuthorizationContext app = user.appContexts().stream()
                .filter(context -> systemCode.equals(context.applicationCode())
                        || systemCode.equals(context.applicationId()))
                .findFirst()
                .orElse(null);
        if (app == null) {
            throw new Rbac3RuleViolation("AUTHORIZATION_DENIED");
        }
        Set<String> permissions = app.permissions();
        Instant generatedAt = clock.instant();
        if (!user.expiresAt().isAfter(generatedAt)) {
            throw new Rbac3RuleViolation("AUTH_SNAPSHOT_EXPIRED");
        }
        Instant expiresAt = user.expiresAt();
        return new SystemAuthorizationSnapshot(
                tenantId,
                identitySub,
                record.userId(),
                systemCode,
                user.authVersion(),
                user.policyVersion(),
                app.effectiveRoleIds(),
                null,
                app.landingRouteCode(),
                permissions,
                Set.copyOf(app.resourceCodes()),
                app.dataScopes(),
                app.fieldPolicies(),
                user.checksum(),
                generatedAt,
                expiresAt);
    }

}
