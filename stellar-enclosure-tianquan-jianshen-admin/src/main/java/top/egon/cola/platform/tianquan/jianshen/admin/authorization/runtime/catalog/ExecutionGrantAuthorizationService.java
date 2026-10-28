package top.egon.cola.platform.tianquan.jianshen.admin.authorization.runtime.catalog;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.net.URI;
import java.time.Clock;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import top.egon.cola.platform.tianquan.jianshen.contract.authorization.ExecutionAuthorizationContract;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.PermissionManifest;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.ResourceAccess;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.ResourceType;
import top.egon.cola.platform.tianquan.jianshen.core.rule.Rbac3RuleViolation;
import top.egon.cola.platform.tianquan.jianshen.starter.autoconfigure.Rbac3StarterProperties;
import top.egon.cola.platform.tianquan.jianshen.starter.permission.UserPermissionScopePolicy;
import top.egon.cola.platform.tianquan.shoubing.contract.ServiceIdentityPrincipal;
import top.egon.cola.platform.tianquan.shoubing.contract.ServiceTokenContext;
import top.egon.cola.platform.tianquan.shoubing.contract.execution.ExecutionGrantContract;
import top.egon.cola.platform.tianquan.shoubing.contract.state.IdentityAuthorityScopes;
import top.egon.cola.platform.tianquan.shoubing.starter.autoconfigure.IdpStarterProperties;
import top.egon.cola.platform.tianquan.shoubing.starter.client.IdpServiceOAuth2Client;
import top.egon.cola.platform.tianquan.shoubing.starter.client.IdpServiceTokenRequest;
import top.egon.cola.platform.tianquan.shoubing.starter.execution.HttpExecutionGrantClient;
import top.egon.cola.platform.tianquan.shoubing.starter.security.IdpAuthenticationToken;
import top.egon.cola.platform.tianquan.shoubing.starter.security.TrustedIssuerRegistry;
import top.egon.cola.platform.tianquan.shoubing.starter.state.IdentityAuthorityProperties;

/** Independently resolves an owner-issued intent before evaluating the active catalog and current roles. */
@Service
@ConditionalOnProperty(prefix = "egon.tianquan-jianshen.execution-grants", name = "enabled", havingValue = "true")
public class ExecutionGrantAuthorizationService {
    private final PermissionRuntimeProofService proofs;
    private final PermissionRuntimeSnapshotRepository snapshots;
    private final TrustedIssuerRegistry issuers;
    private final Map<AuthorityKey, HttpExecutionGrantClient> clients;
    private final Map<PolicyKey, ConfiguredPolicy> policies;
    private final Clock clock;

    @Autowired
    public ExecutionGrantAuthorizationService(PermissionRuntimeProofService proofs, PermissionRuntimeSnapshotRepository snapshots,
            ExecutionGrantAuthorizationProperties policies,
            @Qualifier("identityAuthorityProperties") IdentityAuthorityProperties authority,
            @Qualifier("idpStarterProperties") IdpStarterProperties starter,
            @Qualifier("trustedIssuerRegistry") TrustedIssuerRegistry issuers,
            @Qualifier("idpServiceOAuth2Client") IdpServiceOAuth2Client oauth,
            @Qualifier("jacksonObjectMapper") ObjectMapper mapper, @Qualifier("idpClock") Clock clock) {
        this(proofs, snapshots, issuers, clients(authority, starter, issuers, oauth, mapper,
                IdentityAuthorityScopes.EXECUTION_GRANT_RESOLVE), policies, clock);
    }

    ExecutionGrantAuthorizationService(PermissionRuntimeProofService proofs, PermissionRuntimeSnapshotRepository snapshots,
            TrustedIssuerRegistry issuers, Map<AuthorityKey, HttpExecutionGrantClient> clients,
            ExecutionGrantAuthorizationProperties properties, Clock clock) {
        this.proofs = Objects.requireNonNull(proofs, "proofs");
        this.snapshots = Objects.requireNonNull(snapshots, "snapshots");
        this.issuers = Objects.requireNonNull(issuers, "issuers");
        this.clients = Map.copyOf(clients);
        this.clock = Objects.requireNonNull(clock, "clock");
        if (this.clients.isEmpty() || properties == null || !properties.enabled() || properties.policies().isEmpty()) {
            throw new IllegalStateException("EXECUTION_AUTHORIZATION_BINDINGS_REQUIRED");
        }
        Map<PolicyKey, ConfiguredPolicy> configured = new LinkedHashMap<>();
        for (var policy : properties.policies()) {
            var scopes = new UserPermissionScopePolicy(new Rbac3StarterProperties.UserScopePolicyProperties()
                    .setEnabled(true).setPermissionScopes(policy.permissionScopes()));
            configured.put(new PolicyKey(policy.systemCode(), policy.purpose()), new ConfiguredPolicy(policy, scopes));
        }
        this.policies = Map.copyOf(configured);
    }

    public ExecutionAuthorizationContract.Decision decide(ServiceIdentityPrincipal caller, URI issuer,
                                                            ExecutionAuthorizationContract.Request request) {
        Objects.requireNonNull(request, "request");
        var authentication = SecurityContextHolder.getContext().getAuthentication();
        if (!(authentication instanceof IdpAuthenticationToken verified) || !verified.isAuthenticated()
                || verified.getPrincipal() != caller || issuer == null || !issuer.equals(verified.verifiedIssuer())) throw denied();
        var trusted = issuers.findByIssuer(issuer.toASCIIString()).orElseThrow(ExecutionGrantAuthorizationService::denied);
        if (trusted.realmType() != TrustedIssuerRegistry.RealmType.TENANT || !Objects.equals(trusted.tenantId(), caller.tenantId())) throw denied();
        var binding = proofs.policyBinding(caller, issuer, request.systemCode(), ExecutionAuthorizationContract.SERVICE_SCOPE);
        var client = clients.get(new AuthorityKey(issuer, binding.expectedResource()));
        if (client == null) throw unavailable();
        ExecutionGrantContract.Resolution grant;
        try { grant = client.resolve(new ExecutionGrantContract.Ticket(request.grantId(), request.ciphertext())); }
        catch (HttpExecutionGrantClient.ExecutionGrantDeniedException rejected) { throw denied(); }
        catch (RuntimeException failed) { throw unavailable(); }
        Instant now = clock.instant();
        if (!issuer.toASCIIString().equals(grant.issuer()) || !caller.tenantId().equals(Long.toString(grant.tenantId()))
                || !binding.expectedResource().toASCIIString().equals(grant.resource())
                || !sourceMatches(caller, grant.source()) || !grant.grantId().equals(request.grantId())
                || !grant.expiresAt().isAfter(now) || grant.expiresAt().isAfter(grant.intentDeadlineAt())
                || !caller.expiresAt().isAfter(now)) throw denied();
        var policy = policies.get(new PolicyKey(binding.scope().applicationCode(), grant.purpose()));
        if (policy == null || grant.sessionRequired() && policy.definition().sessionResourceKey() == null) throw unavailable();
        var minimum = new java.util.HashSet<>(policy.definition().requiredPermissions());
        if (grant.sessionRequired()) minimum.addAll(policy.definition().sessionPermissions());
        if (minimum.stream().anyMatch(code -> !grant.scopes().containsAll(policy.definition().permissionScopes().get(code)))) throw denied();
        String key = grant.sessionRequired() ? policy.definition().sessionResourceKey() : policy.definition().resourceKey();
        Instant expiry = caller.expiresAt().isBefore(grant.expiresAt()) ? caller.expiresAt() : grant.expiresAt();
        PermissionRuntimeSnapshotRepository.ExecutionView view;
        try { view = snapshots.currentExecution(new VerifiedExecution(binding, issuer, grant.subject(), expiry, key)); }
        catch (Rbac3RuleViolation failure) {
            if (Set.of("IDENTITY_INACTIVE", "APPLICATION_BINDING_DENIED", "ROLE_ACTIVATION_SET_INVALID", "JWT_EXPIRED")
                    .contains(failure.reasonCode())) throw denied();
            throw unavailable();
        }
        var snapshot = view.snapshot();
        requirePolicy(view, binding, grant, key, policy);
        if (snapshot.expiresAt().isAfter(expiry)) throw unavailable();
        now = clock.instant();
        if (!snapshot.expiresAt().isAfter(now) || !grant.expiresAt().isAfter(now) || !caller.expiresAt().isAfter(now)) throw denied();
        if (!issuers.findByIssuer(issuer.toASCIIString()).filter(trusted::equals).isPresent()) throw unavailable();
        return new ExecutionAuthorizationContract.Decision(grant.grantId(), grant.issuer(), Long.toString(grant.tenantId()),
                grant.subject(), grant.resource(), grant.purpose(), grant.intentId(), grant.bindingSha256(), grant.sessionRequired(),
                grant.intentDeadlineAt(), snapshot.expiresAt(), snapshot.authVersion(), snapshot.policyVersion());
    }

    private static void requirePolicy(PermissionRuntimeSnapshotRepository.ExecutionView view, PermissionRuntimeProperties.Binding binding,
                                      ExecutionGrantContract.Resolution grant, String key, ConfiguredPolicy configured) {
        var snapshot = view.snapshot();
        var resource = view.resource();
        if (snapshot.permissionSnapshot() == null || !new top.egon.cola.platform.tianquan.jianshen.contract.authorization.RuntimePolicyBinding(
                        binding.producerId(), binding.producerVersion(), binding.artifactDigest(), binding.policyDigest(), binding.manifestDigest())
                .equals(snapshot.policyBinding())
                || !snapshot.tenantId().equals(Long.toString(grant.tenantId())) || !snapshot.identitySub().equals(grant.subject())
                || !snapshot.systemCode().equals(binding.scope().applicationCode())
                || !snapshot.permissionSnapshot().issuer().equals(grant.issuer())
                || !snapshot.permissionSnapshot().catalogScope().equals(binding.scope()) || !snapshot.resourceCodes().contains(key)
                || snapshot.expiresAt().isAfter(grant.expiresAt())) throw unavailable();
        var policy = configured.definition();
        String path = grant.sessionRequired() ? policy.sessionResourcePath() : policy.resourcePath();
        if (!resource.key().equals(key) || resource.type() != ResourceType.API || resource.access() != ResourceAccess.PROTECTED
                || !resource.allowedPrincipals().contains(PermissionManifest.PrincipalType.USER)
                || !java.util.List.of("POST").equals(resource.target().get("methods"))
                || !java.util.List.of(path).equals(resource.target().get("paths")) || resource.requirement() == null) throw unavailable();
        var permissions = snapshot.permissions();
        var required = new java.util.HashSet<>(policy.requiredPermissions());
        if (grant.sessionRequired()) required.addAll(policy.sessionPermissions());
        var qualified = configured.scopes().qualify(resource, permissions, grant.scopes()).stream()
                .filter(policy.permissionScopes()::containsKey).collect(java.util.stream.Collectors.toUnmodifiableSet());
        if (!permissions.containsAll(required) || !qualified.containsAll(required)
                || !grant.scopes().containsAll(resource.oauthScopes())
                || !configured.scopes().explicitScopesAllow(resource, grant.scopes())
                || !resource.requirement().allows(qualified)) throw denied();
    }

    private static boolean sourceMatches(ServiceIdentityPrincipal caller, ExecutionGrantContract.Source source) {
        return source != null && source.clientId().equals(caller.clientId()) && source.appId().equals(caller.appId())
                && source.businessCode().equals(caller.sourceBizCode()) && source.applicationCode().equals(caller.sourceAppCode())
                && source.environment().equals(caller.sourceEnvironment());
    }

    static Map<AuthorityKey, HttpExecutionGrantClient> clients(IdentityAuthorityProperties authority, IdpStarterProperties starter,
            TrustedIssuerRegistry issuers, IdpServiceOAuth2Client oauth, ObjectMapper mapper, String requiredScope) {
        if (authority == null || starter == null || authority.getBindings() == null || authority.getBindings().size() > 4096) {
            throw new IllegalStateException("EXECUTION_AUTHORIZATION_BINDINGS_INVALID");
        }
        Map<AuthorityKey, HttpExecutionGrantClient> result = new LinkedHashMap<>();
        authority.getBindings().forEach((name, value) -> {
            if (value == null || value.getScopes() == null || !value.getScopes().contains(requiredScope)) return;
            if (name == null || !name.matches("[A-Za-z0-9._-]{1,128}") || value.getIssuer() == null) {
                throw new IllegalStateException("EXECUTION_AUTHORIZATION_BINDING_INVALID");
            }
            var trusted = issuers.findByIssuer(value.getIssuer().toASCIIString())
                    .orElseThrow(() -> new IllegalStateException("EXECUTION_AUTHORIZATION_ISSUER_UNTRUSTED"));
            if (trusted.realmType() != TrustedIssuerRegistry.RealmType.TENANT || value.getContext() != ServiceTokenContext.TENANT
                    || !Objects.equals(value.getTenantId(), trusted.tenantId())) {
                throw new IllegalStateException("EXECUTION_AUTHORIZATION_TENANT_INVALID");
            }
            URI resource = value.getSourceResource() == null ? starter.getResourceUri() : value.getSourceResource();
            if (resource == null || !"https".equalsIgnoreCase(resource.getScheme()) || resource.getHost() == null
                    || resource.getUserInfo() != null || resource.getQuery() != null || resource.getFragment() != null
                    || !resource.normalize().equals(resource)) throw new IllegalStateException("EXECUTION_AUTHORIZATION_RESOURCE_INVALID");
            var context = new IdpServiceTokenRequest(value.getRegistrationId(), starter.getServiceClient().getAppId(), value.getAudience(),
                    value.getContext(), value.getTenantId(), Set.copyOf(value.getScopes()));
            var client = new HttpExecutionGrantClient(authority.getBaseUri(), value.getIssuer(), context, oauth, mapper, authority.getTimeout());
            if (result.putIfAbsent(new AuthorityKey(value.getIssuer(), resource), client) != null) {
                throw new IllegalStateException("EXECUTION_AUTHORIZATION_BINDING_DUPLICATE");
            }
        });
        return Map.copyOf(result);
    }

    private static Rbac3RuleViolation denied() { return new Rbac3RuleViolation("EXECUTION_GRANT_DENIED"); }
    private static Rbac3RuleViolation unavailable() { return new Rbac3RuleViolation("AUTH_RUNTIME_EXECUTION_UNAVAILABLE"); }
    record AuthorityKey(URI issuer, URI resource) { }
    private record PolicyKey(String systemCode, String purpose) { }
    private record ConfiguredPolicy(ExecutionGrantAuthorizationProperties.Policy definition, UserPermissionScopePolicy scopes) { }
    record VerifiedExecution(PermissionRuntimeProperties.Binding binding, URI issuer, String subject, Instant expiresAt, String resourceKey) { }
}
