package top.egon.cola.platform.tianquan.jianshen.admin.authorization.runtime.repository.tianshu;

import lombok.extern.slf4j.Slf4j;
import top.egon.cola.component.tianshu.service.refresh.DdcYamlConfigApplier;
import top.egon.cola.platform.tianquan.jianshen.admin.config.properties.Rbac3AdminProperties;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.runtime.domain.exception.PolicyApplyException;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.runtime.domain.vo.ApplyFailureVO;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.runtime.domain.vo.Rbac3RuntimePolicySnapshotVO;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.runtime.repository.Rbac3RuntimePolicy;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;
import java.util.regex.Pattern;

/**
 * Atomically applies RBAC-only Tianshu settings. Tianquan-Shoubing owns access-token and
 * refresh-token lifetimes, so no token or identity-state keys are accepted here.
 */
@Slf4j
public final class AtomicRbac3RuntimePolicy implements Rbac3RuntimePolicy {

    public static final String MAXIMUM_ACTIVE_ROOTS_KEY = "tianquan-jianshen.maximum-active-roots";
    public static final Set<String> CONFIG_KEYS = Set.of(MAXIMUM_ACTIVE_ROOTS_KEY);
    private static final Pattern UNSIGNED_INTEGER = Pattern.compile("[0-9]+");

    private final AtomicReference<Rbac3RuntimePolicySnapshotVO> snapshot;
    private final AtomicReference<ApplyFailureVO> lastApplyFailure = new AtomicReference<>();

    public AtomicRbac3RuntimePolicy(Rbac3AdminProperties properties) {
        Objects.requireNonNull(properties, "properties");
        snapshot = new AtomicReference<>(new Rbac3RuntimePolicySnapshotVO(
                properties.getMaximumActiveRoots(), Map.of(MAXIMUM_ACTIVE_ROOTS_KEY, 0L)));
    }

    @Override
    public Rbac3RuntimePolicySnapshotVO current() {
        return snapshot.get();
    }

    public Optional<ApplyFailureVO> lastApplyFailure() {
        return Optional.ofNullable(lastApplyFailure.get());
    }

    public synchronized void apply(String key, String rawValue, long version) {
        try {
            snapshot.set(candidate(snapshot.get(), key, rawValue, version));
            ApplyFailureVO previous = lastApplyFailure.get();
            if (previous != null && previous.key().equals(key)) {
                lastApplyFailure.compareAndSet(previous, null);
            }
        } catch (RuntimeException failure) {
            String errorCode = errorCode(failure);
            lastApplyFailure.set(new ApplyFailureVO(safeKey(key), version, errorCode));
            throw new IllegalArgumentException(
                    "Tianquan-Jianshen runtime policy rejected key=" + safeKey(key)
                            + " version=" + version + " code=" + errorCode,
                    failure);
        }
    }

    /** Captures actual runtime material; preparation never mutates the installed policy or diagnostics. */
    synchronized DdcYamlConfigApplier.PreparedLeaf prepare(String key, String rawValue, long version) {
        Rbac3RuntimePolicySnapshotVO previous = snapshot.get();
        ApplyFailureVO previousFailure = lastApplyFailure.get();
        Rbac3RuntimePolicySnapshotVO candidate = candidate(previous, key, rawValue, version);
        ApplyFailureVO committedFailure = previousFailure != null && previousFailure.key().equals(key)
                ? null : previousFailure;
        return new DdcYamlConfigApplier.PreparedLeaf() {
            private boolean committed;
            private boolean rolledBack;

            @Override
            public void commit() {
                synchronized (AtomicRbac3RuntimePolicy.this) {
                    if (committed || rolledBack) {
                        throw new IllegalStateException("POLICY_PREPARED_CHANGE_ALREADY_USED");
                    }
                    if (snapshot.get() != previous || lastApplyFailure.get() != previousFailure) {
                        throw new IllegalStateException("POLICY_PREPARED_STATE_CHANGED");
                    }
                    snapshot.set(candidate);
                    lastApplyFailure.set(committedFailure);
                    committed = true;
                }
            }

            @Override
            public void rollback() {
                synchronized (AtomicRbac3RuntimePolicy.this) {
                    if (!committed || rolledBack) {
                        return;
                    }
                    if (snapshot.get() != candidate || lastApplyFailure.get() != committedFailure) {
                        throw new IllegalStateException("POLICY_ROLLBACK_STATE_CHANGED");
                    }
                    snapshot.set(previous);
                    lastApplyFailure.set(previousFailure);
                    rolledBack = true;
                }
            }
        };
    }

    private static Rbac3RuntimePolicySnapshotVO candidate(Rbac3RuntimePolicySnapshotVO previous,
            String key, String rawValue, long version) {
        if (!CONFIG_KEYS.contains(key)) {
            throw new PolicyApplyException("UNKNOWN_KEY");
        }
        if (version < 0) {
            throw new PolicyApplyException("INVALID_VERSION");
        }
        long value = parse(rawValue);
        if (value < 1 || value > 32) {
            throw new PolicyApplyException("MAXIMUM_ACTIVE_ROOTS_OUT_OF_RANGE");
        }
        Map<String, Long> versions = new LinkedHashMap<>(previous.configVersions());
        versions.put(key, version);
        return new Rbac3RuntimePolicySnapshotVO(Math.toIntExact(value), versions);
    }

    private static long parse(String rawValue) {
        if (rawValue == null || !UNSIGNED_INTEGER.matcher(rawValue).matches()) {
            throw new PolicyApplyException("INVALID_INTEGER");
        }
        try {
            return Long.parseLong(rawValue);
        } catch (NumberFormatException invalid) {
            throw new PolicyApplyException("INVALID_INTEGER", invalid);
        }
    }

    private static String errorCode(RuntimeException failure) {
        if (failure instanceof PolicyApplyException policyFailure) {
            return policyFailure.errorCode();
        }
        return "INVALID_POLICY";
    }

    private static String safeKey(String key) {
        return key != null && CONFIG_KEYS.contains(key) ? key : "<unsupported>";
    }
}
