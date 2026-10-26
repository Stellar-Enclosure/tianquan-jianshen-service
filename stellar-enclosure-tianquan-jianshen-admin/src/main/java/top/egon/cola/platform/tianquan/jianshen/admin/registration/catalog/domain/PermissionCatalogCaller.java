package top.egon.cola.platform.tianquan.jianshen.admin.registration.catalog.domain;

import org.springframework.security.core.Authentication;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.CanonicalJson;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.CatalogScope;
import top.egon.cola.platform.tianquan.jianshen.core.rule.Rbac3RuleViolation;
import top.egon.cola.platform.tianquan.shoubing.contract.ServiceIdentityPrincipal;
import top.egon.cola.platform.tianquan.shoubing.contract.ServiceTokenContext;
import top.egon.cola.platform.tianquan.shoubing.starter.security.IdpAuthenticationToken;

import java.net.URI;
import java.time.Instant;
import java.util.Map;
import java.util.Objects;

/** Carries only an already verified SERVICE identity; request headers cannot supply its issuer. */
public record PermissionCatalogCaller(URI issuer, ServiceIdentityPrincipal principal) {

    public enum Capability {
        REGISTER("tianquan-jianshen:permission-manifest:register"),
        ACTIVATE("tianquan-jianshen:permission-catalog:activate"),
        READ_DESCRIPTOR("tianquan-jianshen:permission-catalog:read"),
        QUALIFY_DEPLOYMENT("tianquan-jianshen:permission-catalog:qualify"),
        CLEAR_PRODUCER("tianquan-jianshen:permission-catalog:clear");

        private final String scope;

        Capability(String scope) {
            this.scope = scope;
        }

        public String scope() {
            return scope;
        }
    }

    public PermissionCatalogCaller {
        Objects.requireNonNull(issuer, "verified issuer");
        Objects.requireNonNull(principal, "principal");
        if (!issuer.isAbsolute() || issuer.getFragment() != null) throw new IllegalArgumentException("invalid verified issuer");
    }

    public static PermissionCatalogCaller from(Authentication authentication) {
        if (!(authentication instanceof IdpAuthenticationToken token) || !token.isAuthenticated()
                || !(token.getPrincipal() instanceof ServiceIdentityPrincipal principal)
                || principal.scopeContext() != ServiceTokenContext.TENANT) {
            throw new Rbac3RuleViolation("SERVICE_IDENTITY_DENIED");
        }
        try {
            return new PermissionCatalogCaller(token.verifiedIssuer(), principal);
        } catch (IllegalArgumentException | IllegalStateException invalid) {
            throw new Rbac3RuleViolation("SERVICE_IDENTITY_DENIED");
        }
    }

    public void require(CatalogScope target, Capability capability, Instant now) {
        if (principal.scopeContext() != ServiceTokenContext.TENANT || !target.tenantId().equals(principal.tenantId())
                || !principal.scopes().contains(capability.scope()) || !now.isBefore(principal.expiresAt())) {
            throw new Rbac3RuleViolation("SERVICE_IDENTITY_DENIED");
        }
    }

    public String bindingDigest() {
        return CanonicalJson.digest(Map.of("issuer", issuer.toString(), "clientId", principal.clientId(),
                "resourceUri", principal.resourceUri().toString()));
    }
}
