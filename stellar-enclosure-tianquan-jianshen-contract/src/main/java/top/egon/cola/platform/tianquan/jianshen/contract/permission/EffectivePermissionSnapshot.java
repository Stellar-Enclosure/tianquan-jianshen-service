package top.egon.cola.platform.tianquan.jianshen.contract.permission;

import com.fasterxml.jackson.annotation.JsonFormat;
import java.net.URI;
import java.time.Instant;
import java.util.List;
import java.util.Objects;

/** Bounded user permission view bound to one verified identity and complete catalog scope. */
public record EffectivePermissionSnapshot(
        String issuer,
        String subject,
        CatalogScope catalogScope,
        String catalogVersion,
        String authVersion,
        String policyVersion,
        ActiveRoleContext activeRoleContext,
        List<String> permissionCodes,
        @JsonFormat(shape = JsonFormat.Shape.STRING) Instant snapshotExpiresAt
) {
    public EffectivePermissionSnapshot {
        URI uri = URI.create(Objects.requireNonNull(issuer, "issuer"));
        if (!"https".equals(uri.getScheme()) || uri.getHost() == null || uri.getUserInfo() != null
                || uri.getQuery() != null || uri.getFragment() != null || issuer.length() > 2048) {
            throw new IllegalArgumentException("issuer is invalid");
        }
        if (subject == null || subject.isBlank() || subject.length() > 256 || !subject.equals(subject.trim())) {
            throw new IllegalArgumentException("subject is invalid");
        }
        Objects.requireNonNull(catalogScope, "catalogScope");
        catalogVersion = ManifestChecks.decimal(catalogVersion, "catalogVersion", false);
        authVersion = ManifestChecks.decimal(authVersion, "authVersion", true);
        policyVersion = ManifestChecks.decimal(policyVersion, "policyVersion", true);
        Objects.requireNonNull(activeRoleContext, "activeRoleContext");
        if (!catalogScope.applicationCode().equals(activeRoleContext.applicationCode())) {
            throw new IllegalArgumentException("activeRoleContext application differs from catalog scope");
        }
        permissionCodes = ManifestChecks.identifiers(permissionCodes, "permissionCodes", 100_000, 128);
        Objects.requireNonNull(snapshotExpiresAt, "snapshotExpiresAt");
    }

    public record ActiveRoleContext(String applicationCode, List<String> rootRoleIds, List<String> effectiveRoleIds) {
        public ActiveRoleContext {
            applicationCode = ManifestChecks.identifier(applicationCode, "applicationCode", 128);
            rootRoleIds = ids(rootRoleIds, "rootRoleIds");
            effectiveRoleIds = ids(effectiveRoleIds, "effectiveRoleIds");
            if (!effectiveRoleIds.containsAll(rootRoleIds)) {
                throw new IllegalArgumentException("active root roles must be effective");
            }
        }

        private static List<String> ids(List<String> values, String name) {
            Objects.requireNonNull(values, name);
            if (values.size() > 4096) throw new IllegalArgumentException(name + " exceeds limit");
            return values.stream().map(value -> ManifestChecks.decimal(value, name, false)).distinct().sorted().toList();
        }
    }
}
