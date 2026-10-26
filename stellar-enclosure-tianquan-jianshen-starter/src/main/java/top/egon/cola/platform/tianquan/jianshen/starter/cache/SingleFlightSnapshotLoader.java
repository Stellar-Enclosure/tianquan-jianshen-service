package top.egon.cola.platform.tianquan.jianshen.starter.cache;

import top.egon.cola.platform.tianquan.shoubing.contract.IdentityPrincipal;
import top.egon.cola.platform.tianquan.shoubing.starter.security.VerifiedUserTokenCarrier;
import top.egon.cola.platform.tianquan.jianshen.contract.authorization.SystemAuthorizationSnapshot;
import top.egon.cola.platform.tianquan.jianshen.starter.client.Rbac3AuthorizationClient;
import java.time.Clock;
import java.time.Duration;
import java.util.Objects;

/** Every authorization boundary reads the SQL owner; expired or cached state cannot provide failure grace. */
public final class SingleFlightSnapshotLoader {
    private final Rbac3AuthorizationClient client;
    private final String systemCode;
    private final Clock clock;

    public SingleFlightSnapshotLoader(Rbac3AuthorizationClient client, String systemCode, Clock clock) {
        this.client = Objects.requireNonNull(client, "client");
        if (systemCode == null || systemCode.isBlank()) throw new IllegalArgumentException("systemCode is required");
        this.systemCode = systemCode;
        this.clock = Objects.requireNonNull(clock, "clock");
    }

    /** Retains source compatibility while deliberately retiring both shared and near authorization caches. */
    public SingleFlightSnapshotLoader(AuthorizationSnapshotCache cache, Rbac3AuthorizationClient client,
                                      String systemCode, Duration cacheTtl, Clock clock) {
        this(client, systemCode, clock);
    }

    public SystemAuthorizationSnapshot load(IdentityPrincipal principal) {
        return load(principal, VerifiedUserTokenCarrier.currentOrNull());
    }

    public SystemAuthorizationSnapshot load(IdentityPrincipal principal, String userAccessToken) {
        Objects.requireNonNull(principal, "principal");
        if (userAccessToken == null || userAccessToken.isBlank()) {
            throw new Rbac3AuthorizationClient.AuthorizationUnavailableException("TIANQUAN_JIANSHEN_USER_TOKEN_UNAVAILABLE");
        }
        try {
            SystemAuthorizationSnapshot snapshot = client.fetch(systemCode, principal, userAccessToken);
            if (snapshot == null || !systemCode.equals(snapshot.systemCode())
                    || !principal.tenantId().equals(snapshot.tenantId()) || !principal.subject().equals(snapshot.identitySub())
                    || snapshot.permissionSnapshot() == null || snapshot.policyBinding() == null
                    || !snapshot.expiresAt().isAfter(clock.instant()) || snapshot.expiresAt().isAfter(principal.expiresAt())) {
                throw new Rbac3AuthorizationClient.AuthorizationDeniedException("TIANQUAN_JIANSHEN_AUTHORIZATION_BINDING_MISMATCH");
            }
            return snapshot;
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
            throw new Rbac3AuthorizationClient.AuthorizationUnavailableException("TIANQUAN_JIANSHEN_AUTHORIZATION_FETCH_INTERRUPTED", interrupted);
        }
    }
}
