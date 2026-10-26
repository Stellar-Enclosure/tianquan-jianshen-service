package top.egon.cola.platform.tianquan.jianshen.admin.registration.catalog.service;

import top.egon.cola.platform.tianquan.jianshen.admin.registration.catalog.repository.CatalogAdministrationGuard;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import top.egon.cola.platform.tianquan.jianshen.admin.audit.domain.dto.AuditCommandDTO;
import top.egon.cola.platform.tianquan.jianshen.admin.audit.service.AuditQueryService;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.runtime.domain.vo.AuthorizationEventVO;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.runtime.repository.AuthorizationEventPublisher;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.runtime.state.repository.TenantAuthorizationStateRepository;
import top.egon.cola.platform.tianquan.jianshen.admin.registration.catalog.domain.PermissionCatalogCaller;
import top.egon.cola.platform.tianquan.jianshen.admin.registration.catalog.repository.DeploymentQualificationRepository;
import top.egon.cola.platform.tianquan.jianshen.admin.registration.catalog.repository.PermissionCatalogActivationRepository;
import top.egon.cola.platform.tianquan.jianshen.admin.registration.catalog.repository.PermissionCatalogScopeRepository;
import top.egon.cola.platform.tianquan.jianshen.admin.registration.catalog.repository.PermissionManifestRepository;
import top.egon.cola.platform.tianquan.jianshen.admin.shared.domain.DatabaseClock;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.ActivationDescriptor;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.CatalogActivationRequest;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.CatalogScope;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.ManifestRegistrationRequest;
import top.egon.cola.platform.tianquan.jianshen.core.registration.PermissionManifestDiff;
import top.egon.cola.platform.tianquan.jianshen.core.rule.Rbac3RuleViolation;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;
import java.util.Set;
import java.util.HashSet;
import java.time.Instant;
import top.egon.cola.platform.tianquan.jianshen.starter.security.Rbac3UserDetails;

/** The only catalog switch: current grants, exact receipts, deployment proofs and closure precede the local CAS. */
@Service
public class PermissionCatalogActivationService {
    private final PermissionCatalogScopeRepository scopes;
    private final PermissionManifestRepository manifests;
    private final DeploymentQualificationRepository qualifications;
    private final PermissionCatalogActivationRepository activations;
    private final TenantAuthorizationStateRepository policy;
    private final AuthorizationEventPublisher events;
    private final AuditQueryService audit;
    public static final String READ = "system:permission-catalog:read";
    public static final String ACTIVATE = "system:permission-catalog:activate";
    public static final String MANAGE = "system:permission-catalog:manage";
    private final DatabaseClock clock;
    private final CatalogAdministrationGuard administration;

    private record ActivationAuthority(String actor, String principalType,
            Map<String, PermissionCatalogScopeRepository.Owner> owners, Set<String> expansionAllowed, Set<String> clearAllowed) { }

    public PermissionCatalogActivationService(PermissionCatalogScopeRepository scopes, PermissionManifestRepository manifests,
            DeploymentQualificationRepository qualifications, PermissionCatalogActivationRepository activations,
            TenantAuthorizationStateRepository policy, AuthorizationEventPublisher events, AuditQueryService audit, DatabaseClock clock, CatalogAdministrationGuard administration) {
        this.scopes = scopes;
        this.manifests = manifests;
        this.qualifications = qualifications;
        this.activations = activations;
        this.policy = policy;
        this.events = events;
        this.audit = audit;
        this.clock = clock;
        this.administration = administration;
    }

    @Transactional
    public ActivationDescriptor activate(CatalogActivationRequest request, PermissionCatalogCaller caller) {
        var now = clock.transactionNow();
        var owners = new LinkedHashMap<String, PermissionCatalogScopeRepository.Owner>();
        Set<String> expansion = new HashSet<>();
        Set<String> clear = new HashSet<>();
        for (var producer : request.producers()) {
            var authorized = scopes.authorize(request.target(), producer.producerId(), caller, PermissionCatalogCaller.Capability.ACTIVATE, now);
            owners.put(producer.producerId(), authorized.owner());
            if (authorized.grant().allowPermissionExpansion()) expansion.add(producer.producerId());
            if (authorized.grant().capabilities().contains(PermissionCatalogCaller.Capability.CLEAR_PRODUCER.name())
                    && caller.principal().scopes().contains(PermissionCatalogCaller.Capability.CLEAR_PRODUCER.scope())) clear.add(producer.producerId());
        }
        return activateAuthorized(request, new ActivationAuthority("service:" + caller.bindingDigest(), "SERVICE", owners, expansion, clear), now);
    }

    @Transactional
    public ActivationDescriptor activateAdministrator(CatalogActivationRequest request, Rbac3UserDetails actor) {
        var now = clock.transactionNow();
        administration.require(request.target(), actor, ACTIVATE, now);
        var owners = new LinkedHashMap<String, PermissionCatalogScopeRepository.Owner>();
        for (var producer : request.producers()) owners.put(producer.producerId(), scopes.lockOwner(request.target(), producer.producerId()));
        Set<String> managed = actor.hasPermission(MANAGE) ? Set.copyOf(owners.keySet()) : Set.of();
        return activateAuthorized(request, new ActivationAuthority(actor.rbac3UserId(), "USER", owners, managed, managed), now);
    }

    private ActivationDescriptor activateAuthorized(CatalogActivationRequest request, ActivationAuthority authority, Instant now) {
        var owners = authority.owners();
        var previousOperation = activations.operation(request.target(), request.operationId());
        if (previousOperation.isPresent()) {
            if (!previousOperation.get().requestDigest().equals(request.requestDigest())) throw new Rbac3RuleViolation("IDEMPOTENCY_CONFLICT");
            return previousOperation.get().descriptor();
        }
        long expected = Long.parseLong(request.expectedActiveRevision());
        if (owners.values().stream().anyMatch(owner -> owner.activeRevision() != expected)) {
            throw new Rbac3RuleViolation("RESOURCE_VERSION_CONFLICT");
        }
        activations.requireComplete(request);
        var grantedCodes = manifests.grantedCodes(request.target());
        var members = new ArrayList<ActivationDescriptor.ProducerVersion>();
        for (var selected : request.producers()) {
            long revision = Long.parseLong(selected.producerVersion());
            var candidate = manifests.findVersion(request.target(), selected.producerId(), revision)
                    .orElseThrow(() -> new Rbac3RuleViolation("RESOURCE_NOT_FOUND"));
            if (!"READY".equals(candidate.state())) throw new Rbac3RuleViolation("AUTH_SNAPSHOT_NOT_READY");
            var source = manifests.sourceImport(request.target(), selected.producerId(), revision);
            var receipt = manifests.sourceReceipt(request.target(), selected.producerId(), revision)
                    .orElseThrow(() -> new Rbac3RuleViolation("AUTH_SNAPSHOT_NOT_READY"));
            if (!receipt.matches(source)) throw new Rbac3RuleViolation("RESOURCE_MANIFEST_CONFLICT");
            var proof = qualifications.requireTrusted(request.target(), selected.producerId(), revision,
                    Long.parseLong(selected.qualificationId()), now);
            if (!proof.attestation().manifestDigest().equals(candidate.digests().manifestDigest())
                    || !proof.attestation().policyDigest().equals(candidate.digests().policyDigest())
                    || !proof.attestation().commit().equals(candidate.manifest().artifact().commit())
                    || !proof.attestation().buildId().equals(candidate.manifest().artifact().buildId())) {
                throw new Rbac3RuleViolation("RESOURCE_MANIFEST_CONFLICT");
            }
            var old = manifests.activeManifest(request.target(), selected.producerId()).orElse(null);
            var diff = new PermissionManifestDiff().compare(old, candidate.manifest(), grantedCodes);
            if (diff.conflicts()) throw new Rbac3RuleViolation("RESOURCE_MANIFEST_CONFLICT");
            if (diff.authorizationExpansion() && !authority.expansionAllowed().contains(selected.producerId())) {
                throw new Rbac3RuleViolation(authority.principalType().equals("SERVICE") ? "SERVICE_IDENTITY_DENIED" : "PERMISSION_DENIED");
            }
            if (candidate.manifest().producer().clearIntent() && !authority.clearAllowed().contains(selected.producerId())) {
                throw new Rbac3RuleViolation("PERMISSION_DENIED");
            }
            members.add(new ActivationDescriptor.ProducerVersion(selected.producerId(), selected.producerVersion(),
                    receipt.sourceVersion(), candidate.digests(), selected.qualificationId(), proof.attestation().artifactDigest()));
        }
        activations.requireReferenceClosure(request);
        String actor = authority.actor();
        long policyVersion = policy.increment(Long.parseLong(request.target().tenantId()), actor);
        if (owners.values().stream().anyMatch(owner -> policyVersion <= owner.policyVersion())) {
            throw new Rbac3RuleViolation("AUTH_RUNTIME_UNAVAILABLE");
        }
        var descriptor = new ActivationDescriptor(request.target(), Long.toString(Math.addExact(expected, 1)), request.operationId(),
                Long.toString(policyVersion), now, members);
        activations.save(request, descriptor, actor);
        events.enqueue(new AuthorizationEventVO(request.target().tenantId(), "CATALOG_SCOPE", request.target().catalogScopeId(),
                "CATALOG_ACTIVATION_CHANGED", Map.of("catalogScopeId", request.target().catalogScopeId(),
                "catalogVersion", descriptor.activationVersion(), "policyVersion", descriptor.policyVersion(),
                "aggregateVersion", descriptor.policyVersion()), request.operationId()));
        audit.record(new AuditCommandDTO(request.target().tenantId(), "PERMISSION_CATALOG_ACTIVATED", "SUCCESS", "INFO", authority.principalType(),
                actor, "CATALOG_SCOPE", request.target().catalogScopeId(), null, "ALLOW", request.operationId(), request.operationId(), Map.of(),
                Map.of("scope", ManifestRegistrationRequest.targetMap(request.target()), "activationVersion", descriptor.activationVersion(),
                        "policyVersion", descriptor.policyVersion(), "descriptorDigest", descriptor.digest()), now));
        return descriptor;
    }

    @Transactional
    public ActivationDescriptor descriptor(CatalogScope scope, String producer, long version, PermissionCatalogCaller caller) {
        scopes.authorize(scope, producer, caller, PermissionCatalogCaller.Capability.READ_DESCRIPTOR, clock.transactionNow());
        var descriptor = activations.require(scope, version);
        requireMember(descriptor, producer);
        return descriptor;
    }

    @Transactional
    public ActivationDescriptor operation(CatalogScope scope, String producer, String operationId, PermissionCatalogCaller caller) {
        if (!UUID.fromString(operationId).toString().equals(operationId)) throw new IllegalArgumentException("invalid operationId");
        scopes.authorize(scope, producer, caller, PermissionCatalogCaller.Capability.READ_DESCRIPTOR, clock.transactionNow());
        var descriptor = activations.operation(scope, operationId).orElseThrow(() -> new Rbac3RuleViolation("RESOURCE_NOT_FOUND")).descriptor();
        requireMember(descriptor, producer);
        return descriptor;
    }

    @Transactional
    public PermissionCatalogActivationRepository.History history(CatalogScope scope, String producer, long before, int limit, PermissionCatalogCaller caller) {
        scopes.authorize(scope, producer, caller, PermissionCatalogCaller.Capability.READ_DESCRIPTOR, clock.transactionNow());
        var history = activations.history(scope, before, limit);
        history.versions().forEach(descriptor -> requireMember(descriptor, producer));
        return history;
    }

    @Transactional
    public ActivationDescriptor administratorOperation(CatalogScope scope, String operationId, Rbac3UserDetails actor) {
        if (!UUID.fromString(operationId).toString().equals(operationId)) throw new IllegalArgumentException("invalid operationId");
        administration.require(scope, actor, READ, clock.transactionNow());
        return activations.operation(scope, operationId).orElseThrow(() -> new Rbac3RuleViolation("RESOURCE_NOT_FOUND")).descriptor();
    }

    @Transactional
    public PermissionCatalogActivationRepository.History administratorHistory(CatalogScope scope, long before, int limit, Rbac3UserDetails actor) {
        administration.require(scope, actor, READ, clock.transactionNow());
        return activations.history(scope, before, limit);
    }

    private void requireMember(ActivationDescriptor descriptor, String producer) {
        if (descriptor.producers().stream().noneMatch(member -> member.producerId().equals(producer))) {
            throw new Rbac3RuleViolation("SERVICE_IDENTITY_DENIED");
        }
    }
}
