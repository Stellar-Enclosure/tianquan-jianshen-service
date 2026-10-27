package top.egon.cola.platform.tianquan.jianshen.admin.registration.catalog.service;

import top.egon.cola.platform.tianquan.jianshen.contract.permission.annotation.PermissionResource;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.annotation.PermissionGroup;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.annotation.FieldPermissions;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.ResourceType;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.PermissionManifest;

import top.egon.cola.platform.tianquan.jianshen.admin.registration.catalog.repository.CatalogAdministrationGuard;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import top.egon.cola.platform.tianquan.jianshen.admin.registration.catalog.repository.PermissionCatalogQueryRepository;
import top.egon.cola.platform.tianquan.jianshen.admin.registration.catalog.repository.PermissionCatalogScopeRepository;
import top.egon.cola.platform.tianquan.jianshen.admin.registration.catalog.repository.PermissionManifestRepository;
import top.egon.cola.platform.tianquan.jianshen.admin.registration.catalog.repository.PermissionSourceOutboxRepository;
import top.egon.cola.platform.tianquan.jianshen.admin.shared.domain.DatabaseClock;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.CatalogScope;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.ManifestDigests;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.ManifestRegistrationRequest;
import top.egon.cola.platform.tianquan.jianshen.core.registration.PermissionManifestDiff;
import top.egon.cola.platform.tianquan.jianshen.core.rule.Rbac3RuleViolation;
import top.egon.cola.platform.tianquan.jianshen.starter.security.Rbac3UserDetails;

import java.util.List;

@Service
public class PermissionCatalogQueryService {
    public record Producers(@PermissionResource(key = "tianquan-jianshen.field.registration.catalog.service.PermissionCatalogQueryService.Producers.target", type = ResourceType.FIELD,
                labelPage = "tianquan-jianshen.permissions", labelKey = "field.target")
        @FieldPermissions(valueType = PermissionManifest.JsonFieldType.OBJECT,
                plainRead = @PermissionGroup(codes = {"system:permission-catalog:read"}))
        CatalogScope target, @PermissionResource(key = "tianquan-jianshen.field.registration.catalog.service.PermissionCatalogQueryService.Producers.activeRevision", type = ResourceType.FIELD,
                labelPage = "tianquan-jianshen.permissions", labelKey = "field.activeRevision")
        @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
                plainRead = @PermissionGroup(codes = {"system:permission-catalog:read"}))
        String activeRevision, @PermissionResource(key = "tianquan-jianshen.field.registration.catalog.service.PermissionCatalogQueryService.Producers.producers", type = ResourceType.FIELD,
                labelPage = "tianquan-jianshen.permissions", labelKey = "field.producers")
        @FieldPermissions(valueType = PermissionManifest.JsonFieldType.ARRAY,
                plainRead = @PermissionGroup(codes = {"system:permission-catalog:read"}))
        List<PermissionCatalogQueryRepository.Producer> producers) {
        public Producers { producers = List.copyOf(producers); }
    }
    public record Candidates(@PermissionResource(key = "tianquan-jianshen.field.registration.catalog.service.PermissionCatalogQueryService.Candidates.target", type = ResourceType.FIELD,
                labelPage = "tianquan-jianshen.permissions", labelKey = "field.target")
        @FieldPermissions(valueType = PermissionManifest.JsonFieldType.OBJECT,
                plainRead = @PermissionGroup(codes = {"system:permission-catalog:read"}))
        CatalogScope target, @PermissionResource(key = "tianquan-jianshen.field.registration.catalog.service.PermissionCatalogQueryService.Candidates.producerId", type = ResourceType.FIELD,
                labelPage = "tianquan-jianshen.permissions", labelKey = "field.producerId")
        @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
                plainRead = @PermissionGroup(codes = {"system:permission-catalog:read"}))
        String producerId, @PermissionResource(key = "tianquan-jianshen.field.registration.catalog.service.PermissionCatalogQueryService.Candidates.activeRevision", type = ResourceType.FIELD,
                labelPage = "tianquan-jianshen.permissions", labelKey = "field.activeRevision")
        @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
                plainRead = @PermissionGroup(codes = {"system:permission-catalog:read"}))
        String activeRevision, @PermissionResource(key = "tianquan-jianshen.field.registration.catalog.service.PermissionCatalogQueryService.Candidates.producerRevision", type = ResourceType.FIELD,
                labelPage = "tianquan-jianshen.permissions", labelKey = "field.producerRevision")
        @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
                plainRead = @PermissionGroup(codes = {"system:permission-catalog:read"}))
        String producerRevision,
            @PermissionResource(key = "tianquan-jianshen.field.registration.catalog.service.PermissionCatalogQueryService.Candidates.candidates", type = ResourceType.FIELD,
                    labelPage = "tianquan-jianshen.permissions", labelKey = "field.candidates")
            @FieldPermissions(valueType = PermissionManifest.JsonFieldType.ARRAY,
                    plainRead = @PermissionGroup(codes = {"system:permission-catalog:read"}))
            List<PermissionCatalogQueryRepository.Candidate> candidates, @PermissionResource(key = "tianquan-jianshen.field.registration.catalog.service.PermissionCatalogQueryService.Candidates.nextBeforeVersion", type = ResourceType.FIELD,
                labelPage = "tianquan-jianshen.permissions", labelKey = "field.nextBeforeVersion")
        @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
                plainRead = @PermissionGroup(codes = {"system:permission-catalog:read"}))
        String nextBeforeVersion) {
        public Candidates { candidates = List.copyOf(candidates); }
    }
    public record Diff(@PermissionResource(key = "tianquan-jianshen.field.registration.catalog.service.PermissionCatalogQueryService.Diff.target", type = ResourceType.FIELD,
                labelPage = "tianquan-jianshen.permissions", labelKey = "field.target")
        @FieldPermissions(valueType = PermissionManifest.JsonFieldType.OBJECT,
                plainRead = @PermissionGroup(codes = {"system:permission-catalog:read"}))
        CatalogScope target, @PermissionResource(key = "tianquan-jianshen.field.registration.catalog.service.PermissionCatalogQueryService.Diff.producerId", type = ResourceType.FIELD,
                labelPage = "tianquan-jianshen.permissions", labelKey = "field.producerId")
        @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
                plainRead = @PermissionGroup(codes = {"system:permission-catalog:read"}))
        String producerId, @PermissionResource(key = "tianquan-jianshen.field.registration.catalog.service.PermissionCatalogQueryService.Diff.producerVersion", type = ResourceType.FIELD,
                labelPage = "tianquan-jianshen.permissions", labelKey = "field.producerVersion")
        @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
                plainRead = @PermissionGroup(codes = {"system:permission-catalog:read"}))
        String producerVersion, @PermissionResource(key = "tianquan-jianshen.field.registration.catalog.service.PermissionCatalogQueryService.Diff.expectedActiveRevision", type = ResourceType.FIELD,
                labelPage = "tianquan-jianshen.permissions", labelKey = "field.expectedActiveRevision")
        @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
                plainRead = @PermissionGroup(codes = {"system:permission-catalog:read"}))
        String expectedActiveRevision,
                       @PermissionResource(key = "tianquan-jianshen.field.registration.catalog.service.PermissionCatalogQueryService.Diff.digests", type = ResourceType.FIELD,
                               labelPage = "tianquan-jianshen.permissions", labelKey = "field.digests")
                       @FieldPermissions(valueType = PermissionManifest.JsonFieldType.OBJECT,
                               plainRead = @PermissionGroup(codes = {"system:permission-catalog:read"}))
                       ManifestDigests digests, @PermissionResource(key = "tianquan-jianshen.field.registration.catalog.service.PermissionCatalogQueryService.Diff.diff", type = ResourceType.FIELD,
                labelPage = "tianquan-jianshen.permissions", labelKey = "field.diff")
        @FieldPermissions(valueType = PermissionManifest.JsonFieldType.OBJECT,
                plainRead = @PermissionGroup(codes = {"system:permission-catalog:read"}))
        PermissionManifestDiff.Result diff) { }

    private final CatalogAdministrationGuard guard;
    private final PermissionCatalogScopeRepository scopes;
    private final PermissionCatalogQueryRepository queries;
    private final PermissionManifestRepository manifests;
    private final PermissionSourceOutboxRepository outbox;
    private final DatabaseClock clock;

    public PermissionCatalogQueryService(CatalogAdministrationGuard guard, PermissionCatalogScopeRepository scopes,
            PermissionCatalogQueryRepository queries, PermissionManifestRepository manifests, PermissionSourceOutboxRepository outbox, DatabaseClock clock) {
        this.guard = guard;
        this.scopes = scopes;
        this.queries = queries;
        this.manifests = manifests;
        this.outbox = outbox;
        this.clock = clock;
    }

    @Transactional
    public Producers producers(CatalogScope target, Rbac3UserDetails actor) {
        var scope = guard.requireRead(target, actor, PermissionCatalogActivationService.READ, clock.transactionNow());
        return new Producers(target, Long.toString(scope.activeRevision()), queries.producers(target));
    }

    @Transactional
    public Candidates candidates(CatalogScope target, String producer, long beforeVersion, int limit, Rbac3UserDetails actor) {
        new ManifestRegistrationRequest.Target(target, producer);
        var now = clock.transactionNow();
        guard.requireRead(target, actor, PermissionCatalogActivationService.READ, now);
        var owner = scopes.readExistingOwner(target, producer);
        var rows = queries.candidates(target, producer, beforeVersion, limit, now);
        var values = rows.stream().limit(limit).map(row -> {
            var candidate = row.value();
            return candidate.state().equals("METADATA_PENDING") && outbox.dead(target, producer,
                    Long.parseLong(candidate.producerVersion()), row.metadataRevision()) ? candidate.failedDelivery() : candidate;
        }).toList();
        return new Candidates(target, producer, Long.toString(owner.activeRevision()), Long.toString(owner.producerRevision()), values,
                rows.size() > limit ? values.getLast().producerVersion() : null);
    }

    @Transactional
    public Diff diff(CatalogScope target, String producer, long revision, Rbac3UserDetails actor) {
        new ManifestRegistrationRequest.Target(target, producer);
        guard.requireRead(target, actor, PermissionCatalogActivationService.READ, clock.transactionNow());
        var owner = scopes.readExistingOwner(target, producer);
        var candidate = manifests.findVersion(target, producer, revision).orElseThrow(() -> new Rbac3RuleViolation("RESOURCE_NOT_FOUND"));
        var previous = manifests.activeManifest(target, producer).orElse(null);
        return new Diff(target, producer, Long.toString(revision), Long.toString(owner.activeRevision()), candidate.digests(),
                new PermissionManifestDiff().compare(previous, candidate.manifest(), manifests.grantedCodes(target)));
    }
}
