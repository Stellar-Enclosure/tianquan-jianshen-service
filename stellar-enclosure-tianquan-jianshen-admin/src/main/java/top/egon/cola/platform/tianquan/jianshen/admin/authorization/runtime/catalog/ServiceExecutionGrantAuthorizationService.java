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
import top.egon.cola.platform.tianquan.jianshen.contract.authorization.RuntimePolicyBinding;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.PermissionManifest;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.ResourceAccess;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.ResourceType;
import top.egon.cola.platform.tianquan.jianshen.core.rule.Rbac3RuleViolation;
import top.egon.cola.platform.tianquan.shoubing.contract.ServiceIdentityPrincipal;
import top.egon.cola.platform.tianquan.shoubing.contract.execution.ServiceExecutionGrantContract;
import top.egon.cola.platform.tianquan.shoubing.contract.state.IdentityAuthorityScopes;
import top.egon.cola.platform.tianquan.shoubing.starter.autoconfigure.IdpStarterProperties;
import top.egon.cola.platform.tianquan.shoubing.starter.client.IdpServiceOAuth2Client;
import top.egon.cola.platform.tianquan.shoubing.starter.execution.HttpExecutionGrantClient;
import top.egon.cola.platform.tianquan.shoubing.starter.security.IdpAuthenticationToken;
import top.egon.cola.platform.tianquan.shoubing.starter.security.TrustedIssuerRegistry;
import top.egon.cola.platform.tianquan.shoubing.starter.state.IdentityAuthorityProperties;

/** Independently resolves the owner-sealed SERVICE subject and checks its active catalog resource. */
@Service
@ConditionalOnProperty(prefix = "egon.tianquan-jianshen.service-execution-grants", name = "enabled", havingValue = "true")
public class ServiceExecutionGrantAuthorizationService {
    static final String SERVICE_SCOPE = "service:authorization:service-execution";
    private final PermissionRuntimeProofService proofs;
    private final PermissionRuntimeSnapshotRepository snapshots;
    private final TrustedIssuerRegistry issuers;
    private final Map<ExecutionGrantAuthorizationService.AuthorityKey, HttpExecutionGrantClient> clients;
    private final Map<PolicyKey, ServiceExecutionGrantAuthorizationProperties.Policy> policies;
    private final Clock clock;

    @Autowired
    public ServiceExecutionGrantAuthorizationService(PermissionRuntimeProofService proofs, PermissionRuntimeSnapshotRepository snapshots,
            ServiceExecutionGrantAuthorizationProperties properties,
            @Qualifier("identityAuthorityProperties") IdentityAuthorityProperties authority,
            @Qualifier("idpStarterProperties") IdpStarterProperties starter,
            @Qualifier("trustedIssuerRegistry") TrustedIssuerRegistry issuers,
            @Qualifier("idpServiceOAuth2Client") IdpServiceOAuth2Client oauth,
            @Qualifier("jacksonObjectMapper") ObjectMapper mapper, @Qualifier("idpClock") Clock clock) {
        this(proofs, snapshots, issuers, ExecutionGrantAuthorizationService.clients(authority, starter, issuers, oauth, mapper,
                IdentityAuthorityScopes.SERVICE_EXECUTION_GRANT_RESOLVE), properties, clock);
    }

    ServiceExecutionGrantAuthorizationService(PermissionRuntimeProofService proofs, PermissionRuntimeSnapshotRepository snapshots,
            TrustedIssuerRegistry issuers, Map<ExecutionGrantAuthorizationService.AuthorityKey, HttpExecutionGrantClient> clients,
            ServiceExecutionGrantAuthorizationProperties properties, Clock clock) {
        this.proofs = Objects.requireNonNull(proofs, "proofs");
        this.snapshots = Objects.requireNonNull(snapshots, "snapshots");
        this.issuers = Objects.requireNonNull(issuers, "issuers");
        this.clients = Map.copyOf(clients);
        this.clock = Objects.requireNonNull(clock, "clock");
        if (this.clients.isEmpty() || properties == null || !properties.enabled() || properties.policies().isEmpty()) {
            throw new IllegalStateException("SERVICE_EXECUTION_AUTHORIZATION_BINDINGS_REQUIRED");
        }
        Map<PolicyKey, ServiceExecutionGrantAuthorizationProperties.Policy> configured = new LinkedHashMap<>();
        for (var policy : properties.policies()) {
            configured.put(new PolicyKey(policy.issuer(), policy.tenantId(), policy.systemCode(), policy.purpose()), policy);
        }
        this.policies = Map.copyOf(configured);
    }

    Decision decide(ServiceIdentityPrincipal caller, URI issuer, Request request) {
        Objects.requireNonNull(request, "request");
        var authentication = SecurityContextHolder.getContext().getAuthentication();
        if (!(authentication instanceof IdpAuthenticationToken verified) || !verified.isAuthenticated()
                || verified.getPrincipal() != caller || issuer == null) throw denied();
        String verifiedIssuer;
        try { verifiedIssuer = verified.verifiedIssuer().toASCIIString(); }
        catch (IllegalStateException missing) { throw denied(); }
        if (!issuer.toASCIIString().equals(verifiedIssuer)) throw denied();
        var trusted = issuers.findByIssuer(issuer.toASCIIString()).orElseThrow(ServiceExecutionGrantAuthorizationService::denied);
        if (trusted.realmType() != TrustedIssuerRegistry.RealmType.TENANT || !Objects.equals(trusted.tenantId(), caller.tenantId())) throw denied();
        var binding = proofs.policyBinding(caller, issuer, request.systemCode(), SERVICE_SCOPE);
        var client = clients.get(new ExecutionGrantAuthorizationService.AuthorityKey(issuer, binding.expectedResource()));
        if (client == null) throw unavailable();
        ServiceExecutionGrantContract.Resolution grant;
        try { grant = client.resolveService(request.ticket()); }
        catch (HttpExecutionGrantClient.ExecutionGrantDeniedException rejected) { throw denied(); }
        catch (RuntimeException failed) { throw unavailable(); }
        Instant now = clock.instant();
        if (!issuer.toASCIIString().equals(grant.issuer()) || !caller.tenantId().equals(Long.toString(grant.tenantId()))
                || !binding.expectedResource().toASCIIString().equals(grant.resource()) || !sourceMatches(caller, grant.source())
                || !grant.grantId().equals(request.ticket().grantId()) || !grant.expiresAt().isAfter(now)
                || grant.expiresAt().isAfter(grant.intentDeadlineAt()) || !caller.expiresAt().isAfter(now)) throw denied();
        var policy = policies.get(new PolicyKey(grant.issuer(), Long.toString(grant.tenantId()),
                binding.scope().applicationCode(), grant.purpose()));
        if (policy == null || grant.sessionRequired() && policy.sessionResourceKey() == null) throw unavailable();
        if (policy.subjects().stream().noneMatch(subject -> subject.matches(grant.subjectSource()))
                || !grant.scopes().containsAll(policy.requiredScopes())
                || grant.sessionRequired() && !grant.scopes().containsAll(policy.sessionScopes())) throw denied();
        String key = grant.sessionRequired() ? policy.sessionResourceKey() : policy.resourceKey();
        Instant expiry = caller.expiresAt().isBefore(grant.expiresAt()) ? caller.expiresAt() : grant.expiresAt();
        PermissionRuntimeSnapshotRepository.ServiceExecutionView view;
        try { view = snapshots.currentServiceExecution(binding, expiry, key); }
        catch (Rbac3RuleViolation failure) {
            if (Set.of("APPLICATION_BINDING_DENIED", "JWT_EXPIRED").contains(failure.reasonCode())) throw denied();
            throw unavailable();
        }
        requirePolicy(view, binding, grant, key, policy, expiry);
        now = clock.instant();
        if (!view.snapshot().expiresAt().isAfter(now) || !grant.expiresAt().isAfter(now) || !caller.expiresAt().isAfter(now)) throw denied();
        if (!issuers.findByIssuer(issuer.toASCIIString()).filter(trusted::equals).isPresent()) throw unavailable();
        return new Decision(grant.grantId(), grant.issuer(), Long.toString(grant.tenantId()), grant.subject(), grant.subjectSource(),
                grant.resource(), grant.purpose(), grant.intentId(), grant.bindingSha256(), grant.sessionRequired(), grant.intentDeadlineAt(),
                view.snapshot().expiresAt(), Long.parseLong(view.snapshot().catalogVersion()), Long.parseLong(view.snapshot().policyVersion()));
    }

    private static void requirePolicy(PermissionRuntimeSnapshotRepository.ServiceExecutionView view, PermissionRuntimeProperties.Binding binding,
            ServiceExecutionGrantContract.Resolution grant, String key, ServiceExecutionGrantAuthorizationProperties.Policy policy, Instant expiry) {
        if (view == null || view.snapshot() == null || view.resource() == null) throw unavailable();
        var snapshot = view.snapshot();
        var resource = view.resource();
        if (!new RuntimePolicyBinding(binding.producerId(), binding.producerVersion(), binding.artifactDigest(),
                    binding.policyDigest(), binding.manifestDigest()).equals(snapshot.policyBinding())
                || !binding.scope().equals(snapshot.catalogScope()) || !snapshot.resourceKeys().contains(key)
                || snapshot.expiresAt().isAfter(expiry)) throw unavailable();
        String path = grant.sessionRequired() ? policy.sessionResourcePath() : policy.resourcePath();
        if (!resource.key().equals(key) || resource.type() != ResourceType.API || resource.access() != ResourceAccess.PROTECTED
                || !resource.allowedPrincipals().contains(PermissionManifest.PrincipalType.SERVICE)
                || !java.util.List.of("POST").equals(resource.target().get("methods"))
                || !java.util.List.of(path).equals(resource.target().get("paths")) || resource.oauthScopes().isEmpty()) throw unavailable();
        if (!grant.scopes().containsAll(resource.oauthScopes())) throw denied();
    }

    private static boolean sourceMatches(ServiceIdentityPrincipal caller, ServiceExecutionGrantContract.Source source) {
        return source != null && source.clientId().equals(caller.clientId()) && source.appId().equals(caller.appId())
                && source.businessCode().equals(caller.sourceBizCode()) && source.applicationCode().equals(caller.sourceAppCode())
                && source.environment().equals(caller.sourceEnvironment());
    }

    private static Rbac3RuleViolation denied() { return new Rbac3RuleViolation("EXECUTION_GRANT_DENIED"); }
    private static Rbac3RuleViolation unavailable() { return new Rbac3RuleViolation("AUTH_RUNTIME_EXECUTION_UNAVAILABLE"); }
    private record PolicyKey(String issuer, String tenantId, String systemCode, String purpose) { }

    record Request(String systemCode, ServiceExecutionGrantContract.Ticket ticket) {
        Request {
            if (systemCode == null || !systemCode.matches("[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}") || ticket == null) {
                throw new IllegalArgumentException("SERVICE_EXECUTION_AUTHORIZATION_REQUEST_INVALID");
            }
        }
        @Override public String toString() { return "ServiceExecutionAuthorizationRequest[redacted]"; }
    }

    record Decision(String grantId, String issuer, String tenantId, String subject, ServiceExecutionGrantContract.Source subjectSource,
            String resource, String purpose, String intentId, String bindingSha256, boolean sessionRequired,
            Instant deadlineAt, Instant expiresAt, long catalogVersion, long policyVersion) {
        @Override public String toString() { return "ServiceExecutionAuthorizationDecision[redacted]"; }
    }
}
