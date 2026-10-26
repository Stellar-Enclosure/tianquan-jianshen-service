package top.egon.cola.platform.tianquan.jianshen.admin.registration.catalog.service;

import top.egon.cola.platform.tianquan.jianshen.admin.registration.catalog.domain.convertor.PermissionCatalogJson;
import top.egon.cola.platform.tianquan.jianshen.admin.registration.catalog.domain.vo.DeploymentQualificationReceiptVO;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import top.egon.cola.component.common.id.snowflake.SnowflakeIdGenerator;
import top.egon.cola.platform.tianquan.jianshen.admin.audit.domain.dto.AuditCommandDTO;
import top.egon.cola.platform.tianquan.jianshen.admin.audit.service.AuditQueryService;
import top.egon.cola.platform.tianquan.jianshen.admin.registration.catalog.domain.PermissionCatalogCaller;
import top.egon.cola.platform.tianquan.jianshen.admin.registration.catalog.repository.DeploymentQualificationRepository;
import top.egon.cola.platform.tianquan.jianshen.admin.registration.catalog.repository.PermissionCatalogScopeRepository;
import top.egon.cola.platform.tianquan.jianshen.admin.registration.catalog.repository.PermissionManifestRepository;
import top.egon.cola.platform.tianquan.jianshen.admin.shared.domain.DatabaseClock;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.CanonicalJson;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.DeploymentQualificationRequest;
import top.egon.cola.platform.tianquan.jianshen.core.rule.Rbac3RuleViolation;

import java.util.Map;
import java.util.function.LongSupplier;

@Service
public class DeploymentQualificationService {
    private final PermissionCatalogScopeRepository scopes;
    private final PermissionManifestRepository manifests;
    private final DeploymentQualificationRepository qualifications;
    private final PermissionCatalogJson json;
    private final AuditQueryService audit;
    private final DatabaseClock clock;
    private final LongSupplier ids;

    @Autowired
    public DeploymentQualificationService(PermissionCatalogScopeRepository scopes, PermissionManifestRepository manifests,
            DeploymentQualificationRepository qualifications, PermissionCatalogJson json, AuditQueryService audit, DatabaseClock clock) {
        this(scopes, manifests, qualifications, json, audit, clock, SnowflakeIdGenerator::nextLongId);
    }

    DeploymentQualificationService(PermissionCatalogScopeRepository scopes, PermissionManifestRepository manifests,
            DeploymentQualificationRepository qualifications, PermissionCatalogJson json, AuditQueryService audit, DatabaseClock clock, LongSupplier ids) {
        this.scopes = scopes;
        this.manifests = manifests;
        this.qualifications = qualifications;
        this.json = json;
        this.audit = audit;
        this.clock = clock;
        this.ids = ids;
    }

    @Transactional
    public DeploymentQualificationReceiptVO qualify(DeploymentQualificationRequest request, PermissionCatalogCaller caller) {
        var now = clock.transactionNow();
        var authorized = scopes.authorize(request.target(), request.producerId(), caller, PermissionCatalogCaller.Capability.QUALIFY_DEPLOYMENT, now);
        if (!authorized.grant().allowedSourceRefs().contains(request.sourceRef())) throw new Rbac3RuleViolation("SERVICE_IDENTITY_DENIED");
        if (request.readiness().checkedAt().isAfter(now) || request.readiness().checkedAt().isBefore(now.minusSeconds(300))) {
            throw new Rbac3RuleViolation("RESOURCE_VERSION_CONFLICT");
        }
        var candidate = manifests.findVersion(request.target(), request.producerId(), Long.parseLong(request.producerVersion()))
                .orElseThrow(() -> new Rbac3RuleViolation("RESOURCE_NOT_FOUND"));
        if (!"READY".equals(candidate.state()) || !candidate.digests().manifestDigest().equals(request.manifestDigest())
                || !candidate.digests().policyDigest().equals(request.policyDigest())
                || !candidate.manifest().artifact().commit().equals(request.commit()) || !candidate.manifest().artifact().buildId().equals(request.buildId())) {
            throw new Rbac3RuleViolation("RESOURCE_MANIFEST_CONFLICT");
        }
        String digest = CanonicalJson.digestUtf8(json.write(request));
        var existing = qualifications.findCurrent(request.target(), request.producerId(), digest, caller, now);
        if (existing.isPresent()) return existing.get();
        var expiry = now.plusSeconds(900);
        if (caller.principal().expiresAt().isBefore(expiry)) expiry = caller.principal().expiresAt();
        var receipt = new DeploymentQualificationReceiptVO(Long.toString(ids.getAsLong()), digest, request,
                caller.issuer().toString(), caller.principal().clientId(), caller.principal().resourceUri().toString(), now, expiry);
        qualifications.save(receipt);
        audit.record(new AuditCommandDTO(request.target().tenantId(), "PERMISSION_DEPLOYMENT_QUALIFIED", "SUCCESS", "INFO", "SERVICE",
                "service:" + caller.bindingDigest(), "CATALOG_SCOPE", request.target().catalogScopeId(), null, "ALLOW",
                receipt.qualificationId(), receipt.qualificationId(), Map.of(), Map.of("producerId", request.producerId(),
                        "producerVersion", request.producerVersion(), "artifactDigest", request.artifactDigest(),
                        "qualificationId", receipt.qualificationId(), "readinessDigest", request.readiness().digest()), now));
        return receipt;
    }
}
