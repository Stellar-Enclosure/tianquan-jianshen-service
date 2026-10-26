package top.egon.cola.platform.tianquan.jianshen.admin.authorization.runtime.catalog;

import org.springframework.boot.context.properties.ConfigurationProperties;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.CatalogScope;
import java.net.URI;
import java.time.Duration;
import java.util.List;
import java.util.Objects;

/** Finite, deployment-owned runtime bindings. Request values never select identity or catalog authority. */
@ConfigurationProperties("egon.tianquan-jianshen.catalog-runtime")
public record PermissionRuntimeProperties(Duration snapshotTtl, List<Binding> bindings) {
    public PermissionRuntimeProperties {
        snapshotTtl = snapshotTtl == null ? Duration.ofSeconds(30) : snapshotTtl;
        if (snapshotTtl.compareTo(Duration.ofSeconds(1)) < 0 || snapshotTtl.compareTo(Duration.ofMinutes(5)) > 0) {
            throw new IllegalArgumentException("catalog runtime snapshot TTL must be 1s..5m");
        }
        bindings = bindings == null ? List.of() : List.copyOf(bindings);
        if (bindings.size() > 256 || bindings.stream().map(Binding::identity).distinct().count() != bindings.size()) {
            throw new IllegalArgumentException("runtime bindings must be finite and unambiguous");
        }
    }

    public record Binding(CatalogScope scope, URI expectedResource, URI serviceIssuer, String serviceClientId,
            String serviceAppId, String sourceBusinessCode, String sourceApplicationCode, String sourceEnvironment,
            URI receiverResource, String producerId, String producerVersion, String artifactDigest,
            String policyDigest, String manifestDigest, boolean local) {
        public Binding {
            Objects.requireNonNull(scope, "scope");
            secure(expectedResource); secure(receiverResource); secure(serviceIssuer);
            for (String value : List.of(serviceClientId, serviceAppId, sourceBusinessCode, sourceApplicationCode,
                    sourceEnvironment, producerId)) {
                if (value.isBlank() || !value.equals(value.trim()) || value.length() > 200) {
                    throw new IllegalArgumentException("runtime binding identifier is invalid");
                }
            }
            if (producerVersion == null || !producerVersion.matches("[1-9][0-9]{0,18}")) {
                throw new IllegalArgumentException("runtime producer version is invalid");
            }
            Long.parseLong(producerVersion);
            for (String hash : List.of(artifactDigest, policyDigest, manifestDigest)) {
                if (!hash.matches("[0-9a-f]{64}")) throw new IllegalArgumentException("runtime artifact digest is invalid");
            }
        }

        private String identity() {
            return serviceIssuer + "|" + serviceClientId + "|" + scope.tenantId() + "|" + receiverResource;
        }

        private static void secure(URI uri) {
            if (uri == null || !"https".equals(uri.getScheme()) || uri.getHost() == null
                    || uri.getUserInfo() != null || uri.getQuery() != null || uri.getFragment() != null) {
                throw new IllegalArgumentException("runtime binding URI must be exact HTTPS");
            }
        }
    }
}
