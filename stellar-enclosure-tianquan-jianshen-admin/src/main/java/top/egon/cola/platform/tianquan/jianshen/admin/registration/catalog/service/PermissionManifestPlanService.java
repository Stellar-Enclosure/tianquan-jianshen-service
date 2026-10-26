package top.egon.cola.platform.tianquan.jianshen.admin.registration.catalog.service;

import top.egon.cola.platform.tianquan.jianshen.contract.permission.annotation.PermissionResource;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.ResourceAccess;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.ResourceType;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.PermissionManifest;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import top.egon.cola.component.common.id.snowflake.SnowflakeIdGenerator;
import top.egon.cola.platform.tianquan.jianshen.admin.audit.domain.dto.AuditCommandDTO;
import top.egon.cola.platform.tianquan.jianshen.admin.audit.service.AuditQueryService;
import top.egon.cola.platform.tianquan.jianshen.admin.registration.catalog.domain.PermissionCatalogCaller;
import top.egon.cola.platform.tianquan.jianshen.admin.registration.catalog.domain.PermissionRegistrationPlan;
import top.egon.cola.platform.tianquan.jianshen.admin.registration.catalog.repository.PermissionCatalogDefinitionRepository;
import top.egon.cola.platform.tianquan.jianshen.admin.registration.catalog.repository.PermissionCatalogScopeRepository;
import top.egon.cola.platform.tianquan.jianshen.admin.registration.catalog.repository.PermissionManifestRepository;
import top.egon.cola.platform.tianquan.jianshen.admin.shared.domain.DatabaseClock;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.CatalogScope;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.ManifestDigests;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.ManifestRegistrationRequest;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.PermissionManifestCanonicalizer;
import top.egon.cola.platform.tianquan.jianshen.core.registration.PermissionManifestDiff;
import top.egon.cola.platform.tianquan.jianshen.core.rule.Rbac3RuleViolation;

import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.function.LongSupplier;

/** Produces an immutable, expiring review plan without changing any runtime catalog. */
@Service
public class PermissionManifestPlanService {

    public record Result(@PermissionResource(key = "tianquan-jianshen.field.registration.catalog.service.PermissionManifestPlanService.Result.planId", type = ResourceType.FIELD,
                labelPage = "tianquan-jianshen.permissions", labelKey = "field.planId", access = ResourceAccess.PUBLIC,
                allowedPrincipals = {PermissionManifest.PrincipalType.SERVICE}, oauthScopes = {"tianquan-jianshen:permission-manifest:register"})
        String planId, @PermissionResource(key = "tianquan-jianshen.field.registration.catalog.service.PermissionManifestPlanService.Result.target", type = ResourceType.FIELD,
                labelPage = "tianquan-jianshen.permissions", labelKey = "field.target", access = ResourceAccess.PUBLIC,
                allowedPrincipals = {PermissionManifest.PrincipalType.SERVICE}, oauthScopes = {"tianquan-jianshen:permission-manifest:register"})
        CatalogScope target, @PermissionResource(key = "tianquan-jianshen.field.registration.catalog.service.PermissionManifestPlanService.Result.producerId", type = ResourceType.FIELD,
                labelPage = "tianquan-jianshen.permissions", labelKey = "field.producerId", access = ResourceAccess.PUBLIC,
                allowedPrincipals = {PermissionManifest.PrincipalType.SERVICE}, oauthScopes = {"tianquan-jianshen:permission-manifest:register"})
        String producerId, @PermissionResource(key = "tianquan-jianshen.field.registration.catalog.service.PermissionManifestPlanService.Result.expectedProducerRevision", type = ResourceType.FIELD,
                labelPage = "tianquan-jianshen.permissions", labelKey = "field.expectedProducerRevision", access = ResourceAccess.PUBLIC,
                allowedPrincipals = {PermissionManifest.PrincipalType.SERVICE}, oauthScopes = {"tianquan-jianshen:permission-manifest:register"})
        String expectedProducerRevision,
                         @PermissionResource(key = "tianquan-jianshen.field.registration.catalog.service.PermissionManifestPlanService.Result.expectedActiveRevision", type = ResourceType.FIELD,
                                 labelPage = "tianquan-jianshen.permissions", labelKey = "field.expectedActiveRevision", access = ResourceAccess.PUBLIC,
                                 allowedPrincipals = {PermissionManifest.PrincipalType.SERVICE}, oauthScopes = {"tianquan-jianshen:permission-manifest:register"})
                         String expectedActiveRevision, @PermissionResource(key = "tianquan-jianshen.field.registration.catalog.service.PermissionManifestPlanService.Result.digests", type = ResourceType.FIELD,
                labelPage = "tianquan-jianshen.permissions", labelKey = "field.digests", access = ResourceAccess.PUBLIC,
                allowedPrincipals = {PermissionManifest.PrincipalType.SERVICE}, oauthScopes = {"tianquan-jianshen:permission-manifest:register"})
        ManifestDigests digests, @PermissionResource(key = "tianquan-jianshen.field.registration.catalog.service.PermissionManifestPlanService.Result.diff", type = ResourceType.FIELD,
                labelPage = "tianquan-jianshen.permissions", labelKey = "field.diff", access = ResourceAccess.PUBLIC,
                allowedPrincipals = {PermissionManifest.PrincipalType.SERVICE}, oauthScopes = {"tianquan-jianshen:permission-manifest:register"})
        PermissionManifestDiff.Result diff, @PermissionResource(key = "tianquan-jianshen.field.registration.catalog.service.PermissionManifestPlanService.Result.expiresAt", type = ResourceType.FIELD,
                labelPage = "tianquan-jianshen.permissions", labelKey = "field.expiresAt", access = ResourceAccess.PUBLIC,
                allowedPrincipals = {PermissionManifest.PrincipalType.SERVICE}, oauthScopes = {"tianquan-jianshen:permission-manifest:register"})
        @com.fasterxml.jackson.annotation.JsonFormat(shape = com.fasterxml.jackson.annotation.JsonFormat.Shape.STRING)
        Instant expiresAt) { }

    private final PermissionCatalogScopeRepository scopes;
    private final PermissionCatalogDefinitionRepository definitions;
    private final PermissionManifestRepository manifests;
    private final AuditQueryService audit;
    private final DatabaseClock clock;
    private final LongSupplier ids;

    @Autowired
    public PermissionManifestPlanService(PermissionCatalogScopeRepository scopes, PermissionCatalogDefinitionRepository definitions,
                                         PermissionManifestRepository manifests, AuditQueryService audit, DatabaseClock clock) {
        this(scopes, definitions, manifests, audit, clock, SnowflakeIdGenerator::nextLongId);
    }

    PermissionManifestPlanService(PermissionCatalogScopeRepository scopes, PermissionCatalogDefinitionRepository definitions,
                                  PermissionManifestRepository manifests, AuditQueryService audit, DatabaseClock clock, LongSupplier ids) {
        this.scopes = scopes;
        this.definitions = definitions;
        this.manifests = manifests;
        this.audit = audit;
        this.clock = clock;
        this.ids = ids;
    }

    @Transactional
    public Result plan(ManifestRegistrationRequest.Plan request, PermissionCatalogCaller caller) {
        Instant now = clock.transactionNow();
        var authorized = scopes.authorize(request.target(), request.manifest().producer().id(), caller,
                PermissionCatalogCaller.Capability.REGISTER, now);
        var owner = authorized.owner();
        requireVersions(request.expectedProducerRevision(), request.expectedActiveRevision(), owner);
        definitions.validate(owner, request.manifest(), definitions.load(request.target()));
        var diff = new PermissionManifestDiff().compare(manifests.activeManifest(request.target(), owner.producerId()).orElse(null),
                request.manifest(), manifests.grantedCodes(request.target()));
        ManifestDigests digests = new PermissionManifestCanonicalizer().digests(request.manifest());
        long id = ids.getAsLong();
        Instant expires = now.plus(Duration.ofMinutes(5));
        String actor = "service:" + caller.bindingDigest();
        manifests.savePlan(new PermissionRegistrationPlan(id, request, owner.ownerVersion(), authorized.grant().id(),
                authorized.grant().version(), digests, diff, expires, now, actor));
        audit.record(new AuditCommandDTO(request.target().tenantId(), "PERMISSION_MANIFEST_PLAN_CREATED", "SUCCESS", "INFO", "SERVICE",
                actor, "CATALOG_SCOPE", request.target().catalogScopeId(), null, "ALLOW", Long.toString(id), Long.toString(id), Map.of(),
                Map.of("scope", ManifestRegistrationRequest.targetMap(request.target()), "producerId", owner.producerId(),
                        "manifestDigest", digests.manifestDigest(), "authorizationExpansion", diff.authorizationExpansion()), now));
        return new Result(Long.toString(id), request.target(), owner.producerId(), request.expectedProducerRevision(),
                request.expectedActiveRevision(), digests, diff, expires);
    }

    static void requireVersions(String producerRevision, String activeRevision, PermissionCatalogScopeRepository.Owner owner) {
        if (Long.parseLong(producerRevision) != owner.producerRevision() || Long.parseLong(activeRevision) != owner.activeRevision()) {
            throw new Rbac3RuleViolation("RESOURCE_VERSION_CONFLICT");
        }
    }
}
