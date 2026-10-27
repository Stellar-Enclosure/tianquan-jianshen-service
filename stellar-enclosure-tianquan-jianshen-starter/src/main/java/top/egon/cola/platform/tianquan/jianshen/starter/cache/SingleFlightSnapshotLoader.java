package top.egon.cola.platform.tianquan.jianshen.starter.cache;

import java.time.Clock;
import java.time.Duration;
import top.egon.cola.platform.tianquan.jianshen.starter.client.Rbac3AuthorizationClient;

/**
 * Compatibility name for {@link AuthorizationSnapshotLoader}; no request coalescing or authorization cache is used.
 * @deprecated use {@link AuthorizationSnapshotLoader} for new integrations.
 */
@Deprecated(since = "0.0.1", forRemoval = false)
public final class SingleFlightSnapshotLoader extends AuthorizationSnapshotLoader {
    public SingleFlightSnapshotLoader(Rbac3AuthorizationClient client, String systemCode, Clock clock) {
        super(client, systemCode, clock);
    }

    /** Retains the legacy constructor without restoring cached authorization or failure grace. */
    public SingleFlightSnapshotLoader(AuthorizationSnapshotCache cache, Rbac3AuthorizationClient client,
            String systemCode, Duration cacheTtl, Clock clock) {
        super(client, systemCode, clock);
    }
}
