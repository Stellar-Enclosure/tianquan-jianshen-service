package top.egon.cola.platform.tianquan.jianshen.admin.authorization.runtime.repository.postgresql;

import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.runtime.activation.domain.vo.RuntimePublicationVO;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.runtime.activation.repository.RoleActivationRuntimeRepository;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.runtime.decision.domain.vo.SnapshotRecordVO;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.runtime.decision.repository.AuthorizationSnapshotRepository;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.runtime.decision.repository.FenceVerifier;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.runtime.domain.dto.PublishCommandDTO;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.runtime.domain.vo.PublishResultVO;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.runtime.domain.vo.UserSnapshotProjectionVO;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.runtime.repository.InitialAuthorizationContextRepository;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.runtime.repository.RuntimePublicationRepository;
import top.egon.cola.platform.tianquan.jianshen.core.rule.Rbac3RuleViolation;
import java.time.Clock;
import java.time.Duration;
import java.util.Map;
import java.util.Objects;

/** Same-database publication and fence. A failed or expired publication never becomes an authorization head. */
@Repository
@Transactional
public class PostgresqlAuthorizationRuntimeRepository implements RoleActivationRuntimeRepository,
        AuthorizationSnapshotRepository, FenceVerifier, RuntimePublicationRepository {
    private final PostgresqlRuntimeProjectionRepository projections;
    private final InitialAuthorizationContextRepository authority;
    private final Clock clock;

    public PostgresqlAuthorizationRuntimeRepository(PostgresqlRuntimeProjectionRepository projections,
            InitialAuthorizationContextRepository authority, Clock clock) {
        this.projections = projections;
        this.authority = authority;
        this.clock = clock;
    }

    @Override
    public void publish(RuntimePublicationVO publication) {
        publish(new PublishCommandDTO(publication.tenantId(), publication.identitySub(), publication.userId(),
                publication.authVersion(), publication.policyVersion(), publication.projection()));
    }

    @Override
    public PublishResultVO publish(PublishCommandDTO command) {
        UserSnapshotProjectionVO value = Objects.requireNonNull(command.projection(), "projection");
        var user = value.user();
        var snapshot = value.snapshot();
        var gateway = value.gatewayScope();
        if (!command.tenantId().equals(user.tenantId()) || !command.identitySub().equals(user.identitySub())
                || !command.userId().equals(user.userId()) || command.authVersion() != user.authVersion()
                || command.policyVersion() != user.policyVersion() || !"ACTIVE".equals(user.status())
                || !user.tenantId().equals(snapshot.tenantId()) || !user.identitySub().equals(snapshot.identitySub())
                || !user.userId().equals(snapshot.rbacUserId()) || user.authVersion() != snapshot.authVersion()
                || user.policyVersion() != snapshot.policyVersion() || !user.expiresAt().equals(snapshot.expiresAt())
                || !user.tenantId().equals(gateway.tenantId()) || !user.identitySub().equals(gateway.identitySub())
                || !user.userId().equals(gateway.rbacUserId()) || user.authVersion() != gateway.authVersion()
                || user.policyVersion() != gateway.policyVersion() || !user.expiresAt().equals(gateway.expiresAt())
                || !snapshot.generatedAt().equals(gateway.generatedAt()) || !snapshot.expiresAt().isAfter(clock.instant())) {
            throw new IllegalArgumentException("authorization publication identity/version/expiry mismatch");
        }
        var previous = projections.lock("USER", key(user.tenantId(), user.identitySub()), user.tenantId());
        requireCurrent(user.tenantId(), user.identitySub(), user.userId(), user.authVersion(), user.policyVersion());
        if (previous.authVersion() > user.authVersion() || previous.policyVersion() > user.policyVersion()) {
            throw new Rbac3RuleViolation("AUTH_RUNTIME_VERSION_CONFLICT");
        }
        projections.save("USER", key(user.tenantId(), user.identitySub()), user.tenantId(), user.authVersion(),
                user.policyVersion(), Map.of("projection", value), true, clock.instant());
        return new PublishResultVO(true, snapshot.checksum());
    }

    @Override
    public void createFence(String tenantId, String identitySub, String mutationId, Duration ttl) {
        if (mutationId == null || mutationId.isBlank() || ttl.isNegative() || ttl.isZero()) {
            throw new IllegalArgumentException("invalid authorization fence");
        }
        var previous = projections.lock("USER", key(tenantId, identitySub), tenantId);
        // A fence is released by successful publication, never by elapsed wall-clock time.
        projections.save("USER", key(tenantId, identitySub), tenantId, previous.authVersion(), previous.policyVersion(),
                Map.of("fence", mutationId), false, clock.instant());
    }

    @Override
    @Transactional(readOnly = true)
    public boolean isFenced(String tenantId, String identitySub) {
        return projections.read("USER", key(tenantId, identitySub), tenantId).map(value -> !value.ready()).orElse(true);
    }

    public void removeFence(String tenantId, String identitySub) {
        var current = projections.lock("USER", key(tenantId, identitySub), tenantId);
        if (!current.ready()) throw new Rbac3RuleViolation("AUTH_PROPAGATION_PENDING");
        load(tenantId, identitySub);
    }

    @Override
    public void invalidate(String tenantId, String identitySub, String userId, long authVersion, long policyVersion) {
        var current = projections.lock("USER", key(tenantId, identitySub), tenantId);
        projections.save("USER", key(tenantId, identitySub), tenantId, Math.max(authVersion, current.authVersion()),
                Math.max(policyVersion, current.policyVersion()), Map.of("invalidated", true), false, clock.instant());
    }

    @Override
    @Transactional(readOnly = true)
    public SnapshotRecordVO load(String tenantId, String identitySub) {
        var current = projections.read("USER", key(tenantId, identitySub), tenantId)
                .orElseThrow(() -> new Rbac3RuleViolation("AUTH_SNAPSHOT_NOT_READY"));
        if (!current.ready()) throw new Rbac3RuleViolation("AUTH_PROPAGATION_PENDING");
        UserSnapshotProjectionVO value = projections.convert(current.payload().get("projection"), UserSnapshotProjectionVO.class);
        if (value == null || !tenantId.equals(value.user().tenantId()) || !identitySub.equals(value.user().identitySub())
                || !value.snapshot().expiresAt().isAfter(clock.instant())
                || current.authVersion() != value.snapshot().authVersion()
                || current.policyVersion() != value.snapshot().policyVersion()) {
            throw new Rbac3RuleViolation("AUTH_SNAPSHOT_NOT_READY");
        }
        requireCurrent(tenantId, identitySub, value.user().userId(), current.authVersion(), current.policyVersion());
        return new SnapshotRecordVO(tenantId, identitySub, value.user().userId(), value.snapshot());
    }

    private void requireCurrent(String tenantId, String subject, String userId, long auth, long policy) {
        var state = authority.find(tenantId, subject).orElseThrow(() -> new Rbac3RuleViolation("IDENTITY_INACTIVE"));
        if (!userId.equals(state.userId()) || auth != state.authVersion()) throw new Rbac3RuleViolation("AUTH_VERSION_MISMATCH");
        if (policy != state.policyVersion()) throw new Rbac3RuleViolation("POLICY_VERSION_MISMATCH");
    }

    private static String key(String tenant, String subject) {
        if (tenant == null || !tenant.matches("[1-9][0-9]{0,18}") || subject == null || subject.isBlank()) {
            throw new IllegalArgumentException("invalid runtime identity");
        }
        return tenant + ':' + top.egon.cola.platform.tianquan.jianshen.contract.permission.CanonicalJson.digest(Map.of("subject", subject));
    }
}
