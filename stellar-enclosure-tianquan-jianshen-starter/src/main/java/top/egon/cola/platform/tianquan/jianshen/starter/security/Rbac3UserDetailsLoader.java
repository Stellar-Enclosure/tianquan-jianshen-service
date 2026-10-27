package top.egon.cola.platform.tianquan.jianshen.starter.security;

import top.egon.cola.platform.tianquan.shoubing.contract.IdentityPrincipal;
import top.egon.cola.platform.tianquan.jianshen.contract.authorization.SystemAuthorizationSnapshot;
import top.egon.cola.platform.tianquan.jianshen.starter.cache.AuthorizationSnapshotLoader;
import top.egon.cola.platform.tianquan.jianshen.starter.cache.SingleFlightSnapshotLoader;
import top.egon.cola.platform.tianquan.jianshen.starter.client.Rbac3AuthorizationClient;

import java.util.Objects;

/**
 * Assembles a request-scoped {@link Rbac3UserDetails} from the existing authorization snapshot
 * cache. The cache stores authorization facts only; the current AT identity is always supplied
 * by the caller.
 */
public final class Rbac3UserDetailsLoader {

    private final AuthorizationSnapshotLoader snapshots;

    public Rbac3UserDetailsLoader(AuthorizationSnapshotLoader snapshots) {
        this.snapshots = Objects.requireNonNull(snapshots, "snapshots");
    }

    /** @deprecated use the constructor accepting AuthorizationSnapshotLoader. */
    @Deprecated(since = "0.0.1", forRemoval = false)
    public Rbac3UserDetailsLoader(SingleFlightSnapshotLoader snapshots) {
        this((AuthorizationSnapshotLoader) snapshots);
    }

    public Rbac3UserDetails load(IdentityPrincipal identity) {
        Objects.requireNonNull(identity, "identity");
        SystemAuthorizationSnapshot snapshot = snapshots.load(identity);
        if (snapshot == null
                || !identity.subject().equals(snapshot.identitySub())
                || !identity.tenantId().equals(snapshot.tenantId())) {
            throw new Rbac3AuthorizationClient.AuthorizationDeniedException(
                    "TIANQUAN_JIANSHEN_AUTHORIZATION_BINDING_MISMATCH");
        }
        return new Rbac3UserDetails(identity, snapshot);
    }
}
