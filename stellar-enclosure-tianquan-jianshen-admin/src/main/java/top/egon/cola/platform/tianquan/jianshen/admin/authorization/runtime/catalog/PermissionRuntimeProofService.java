package top.egon.cola.platform.tianquan.jianshen.admin.authorization.runtime.catalog;

import org.springframework.stereotype.Service;
import top.egon.cola.platform.tianquan.shoubing.contract.IdentityPrincipal;
import top.egon.cola.platform.tianquan.shoubing.contract.ServiceIdentityPrincipal;
import top.egon.cola.platform.tianquan.shoubing.contract.ServiceTokenContext;
import top.egon.cola.platform.tianquan.shoubing.starter.security.AccessTokenVerification;
import top.egon.cola.platform.tianquan.shoubing.starter.security.IdpJwtVerifier;
import top.egon.cola.platform.tianquan.shoubing.starter.security.IdpObservedVerificationComponent;
import top.egon.cola.platform.tianquan.shoubing.starter.security.TenantIssuerAuthenticationManagerComponent;
import top.egon.cola.platform.tianquan.shoubing.starter.security.VerifiedPrincipalConverter;
import top.egon.cola.platform.tianquan.shoubing.starter.security.impl.DatabaseOAuthRevocationReader;
import top.egon.cola.platform.tianquan.shoubing.starter.state.IdentityAuthorityClientResolver;
import top.egon.cola.platform.tianquan.jianshen.core.rule.Rbac3RuleViolation;
import java.net.URI;
import java.time.Clock;
import java.util.Map;
import java.util.stream.Collectors;

/** Re-verifies the original USER token for the resource selected by a trusted SERVICE tuple. */
@Service
public class PermissionRuntimeProofService {
    private final PermissionRuntimeProperties properties;
    private final Map<URI, IdpJwtVerifier> verifiers;
    private final Clock clock;

    @org.springframework.beans.factory.annotation.Autowired
    public PermissionRuntimeProofService(PermissionRuntimeProperties properties, Clock clock,
            TenantIssuerAuthenticationManagerComponent issuers, IdentityAuthorityClientResolver authority,
            VerifiedPrincipalConverter converter, IdpObservedVerificationComponent observations) {
        this.properties = properties;
        this.clock = clock;
        this.verifiers = properties.bindings().stream().map(PermissionRuntimeProperties.Binding::expectedResource)
                .distinct().collect(Collectors.toUnmodifiableMap(resource -> resource,
                        resource -> IdpJwtVerifier.createDatabaseConfigured(resource, clock, issuers,
                                new DatabaseOAuthRevocationReader(authority, resource), converter, observations)));
    }

    PermissionRuntimeProofService(PermissionRuntimeProperties properties, Map<URI, IdpJwtVerifier> verifiers, Clock clock) {
        this.properties = properties; this.verifiers = Map.copyOf(verifiers); this.clock = clock;
    }

    public VerifiedRequest service(ServiceIdentityPrincipal caller, URI verifiedIssuer, String systemCode, String originalToken) {
        return service(caller, verifiedIssuer, systemCode, originalToken, "service:authorization:snapshot");
    }

    public VerifiedRequest service(ServiceIdentityPrincipal caller, URI verifiedIssuer, String systemCode,
                                   String originalToken, String requiredScope) {
        return verify(policyBinding(caller, verifiedIssuer, systemCode, requiredScope), originalToken);
    }

    public PermissionRuntimeProperties.Binding policyBinding(ServiceIdentityPrincipal caller, URI verifiedIssuer,
                                                              String systemCode, String requiredScope) {
        if (caller == null || caller.scopeContext() != ServiceTokenContext.TENANT || verifiedIssuer == null
                || !caller.expiresAt().isAfter(clock.instant()) || !caller.scopes().contains(requiredScope)) {
            throw new Rbac3RuleViolation("SERVICE_IDENTITY_DENIED");
        }
        var matches = properties.bindings().stream().filter(binding -> binding.serviceIssuer().equals(verifiedIssuer)
                && binding.serviceClientId().equals(caller.clientId()) && binding.serviceAppId().equals(caller.appId())
                && binding.scope().tenantId().equals(caller.tenantId()) && binding.receiverResource().equals(caller.resourceUri())
                && binding.sourceBusinessCode().equals(caller.sourceBizCode())
                && binding.sourceApplicationCode().equals(caller.sourceAppCode())
                && binding.sourceEnvironment().equals(caller.sourceEnvironment())
                && binding.scope().applicationCode().equals(systemCode)).toList();
        if (matches.size() != 1) throw new Rbac3RuleViolation("APPLICATION_BINDING_DENIED");
        return matches.getFirst();
    }

    public VerifiedRequest local(IdentityPrincipal identity, String originalToken) {
        if (identity == null) throw new Rbac3RuleViolation("JWT_INVALID");
        var matches = properties.bindings().stream().filter(binding -> binding.local()
                && binding.scope().tenantId().equals(identity.tenantId())
                && identity.audience().contains(binding.expectedResource().toASCIIString())).toList();
        if (matches.size() != 1) throw new Rbac3RuleViolation("APPLICATION_BINDING_DENIED");
        VerifiedRequest result = verify(matches.getFirst(), originalToken);
        if (!identity.subject().equals(result.user().subject()) || !identity.tokenId().equals(result.user().tokenId())) {
            throw new Rbac3RuleViolation("IDENTITY_SUBJECT_MISMATCH");
        }
        return result;
    }

    public PermissionRuntimeProperties.Binding localPolicy(ServiceIdentityPrincipal caller, URI verifiedIssuer) {
        if (caller == null || caller.scopeContext() != ServiceTokenContext.TENANT || !caller.expiresAt().isAfter(clock.instant())) {
            throw new Rbac3RuleViolation("SERVICE_IDENTITY_DENIED");
        }
        var matches = properties.bindings().stream().filter(binding -> binding.local()
                && binding.scope().tenantId().equals(caller.tenantId()) && binding.expectedResource().equals(caller.resourceUri())
                && binding.serviceIssuer().equals(verifiedIssuer)).toList();
        if (matches.size() != 1) throw new Rbac3RuleViolation("APPLICATION_BINDING_DENIED");
        return matches.getFirst();
    }

    private VerifiedRequest verify(PermissionRuntimeProperties.Binding binding, String token) {
        if (token == null || token.isBlank() || token.length() > 16_384) throw new Rbac3RuleViolation("JWT_INVALID");
        var result = verifiers.get(binding.expectedResource()).verifyUser(token);
        if (result instanceof AccessTokenVerification.Valid<IdentityPrincipal> valid) {
            if (!binding.serviceIssuer().equals(valid.verifiedIssuer()) || !binding.scope().tenantId().equals(valid.principal().tenantId())
                    || !valid.principal().audience().contains(binding.expectedResource().toASCIIString())) {
                throw new Rbac3RuleViolation("IDENTITY_SUBJECT_MISMATCH");
            }
            return new VerifiedRequest(binding, valid.verifiedIssuer(), valid.principal());
        }
        if (result instanceof AccessTokenVerification.Unavailable<?>) throw new Rbac3RuleViolation("AUTH_RUNTIME_UNAVAILABLE");
        if (result instanceof AccessTokenVerification.Expired<?>) throw new Rbac3RuleViolation("JWT_EXPIRED");
        throw new Rbac3RuleViolation("JWT_INVALID");
    }

    public record VerifiedRequest(PermissionRuntimeProperties.Binding binding, URI issuer, IdentityPrincipal user) { }
}
