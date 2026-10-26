package top.egon.cola.platform.tianquan.jianshen.admin.registration.catalog.repository;

import top.egon.cola.platform.tianquan.jianshen.contract.permission.annotation.PermissionResource;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.annotation.PermissionGroup;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.annotation.FieldPermissions;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.ResourceType;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.PermissionManifest;

import jakarta.persistence.EntityManager;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import top.egon.cola.platform.tianquan.jianshen.admin.registration.catalog.domain.convertor.PermissionCatalogJson;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.CatalogScope;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.ManifestDigests;
import top.egon.cola.platform.tianquan.jianshen.core.rule.Rbac3RuleViolation;

import java.time.Instant;
import java.time.OffsetDateTime;
import java.util.List;

/** Bounded administrative history: candidate list queries never return the full manifest payload. */
@Repository
@Transactional(propagation = Propagation.MANDATORY)
public class PermissionCatalogQueryRepository {
    public record Producer(@PermissionResource(key = "tianquan-jianshen.field.registration.catalog.repository.PermissionCatalogQueryRepository.Producer.producerId", type = ResourceType.FIELD,
                labelPage = "tianquan-jianshen.permissions", labelKey = "field.producerId")
        @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
                plainRead = @PermissionGroup(codes = {"system:permission-catalog:read"}))
        String producerId, @PermissionResource(key = "tianquan-jianshen.field.registration.catalog.repository.PermissionCatalogQueryRepository.Producer.kind", type = ResourceType.FIELD,
                labelPage = "tianquan-jianshen.permissions", labelKey = "field.kind")
        @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
                plainRead = @PermissionGroup(codes = {"system:permission-catalog:read"}))
        String kind, @PermissionResource(key = "tianquan-jianshen.field.registration.catalog.repository.PermissionCatalogQueryRepository.Producer.expectedModules", type = ResourceType.FIELD,
                labelPage = "tianquan-jianshen.permissions", labelKey = "field.expectedModules")
        @FieldPermissions(valueType = PermissionManifest.JsonFieldType.ARRAY,
                plainRead = @PermissionGroup(codes = {"system:permission-catalog:read"}))
        List<String> expectedModules, @PermissionResource(key = "tianquan-jianshen.field.registration.catalog.repository.PermissionCatalogQueryRepository.Producer.producerRevision", type = ResourceType.FIELD,
                labelPage = "tianquan-jianshen.permissions", labelKey = "field.producerRevision")
        @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
                plainRead = @PermissionGroup(codes = {"system:permission-catalog:read"}))
        String producerRevision,
                           @PermissionResource(key = "tianquan-jianshen.field.registration.catalog.repository.PermissionCatalogQueryRepository.Producer.ownerVersion", type = ResourceType.FIELD,
                                   labelPage = "tianquan-jianshen.permissions", labelKey = "field.ownerVersion")
                           @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
                                   plainRead = @PermissionGroup(codes = {"system:permission-catalog:read"}))
                           String ownerVersion, @PermissionResource(key = "tianquan-jianshen.field.registration.catalog.repository.PermissionCatalogQueryRepository.Producer.activeProducerVersion", type = ResourceType.FIELD,
                labelPage = "tianquan-jianshen.permissions", labelKey = "field.activeProducerVersion")
        @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
                plainRead = @PermissionGroup(codes = {"system:permission-catalog:read"}))
        String activeProducerVersion) {
        public Producer { expectedModules = List.copyOf(expectedModules); }
    }
    public record Qualification(@PermissionResource(key = "tianquan-jianshen.field.registration.catalog.repository.PermissionCatalogQueryRepository.Qualification.qualificationId", type = ResourceType.FIELD,
                labelPage = "tianquan-jianshen.permissions", labelKey = "field.qualificationId")
        @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
                plainRead = @PermissionGroup(codes = {"system:permission-catalog:read"}))
        String qualificationId, @PermissionResource(key = "tianquan-jianshen.field.registration.catalog.repository.PermissionCatalogQueryRepository.Qualification.artifactDigest", type = ResourceType.FIELD,
                labelPage = "tianquan-jianshen.permissions", labelKey = "field.artifactDigest")
        @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
                plainRead = @PermissionGroup(codes = {"system:permission-catalog:read"}))
        String artifactDigest, @PermissionResource(key = "tianquan-jianshen.field.registration.catalog.repository.PermissionCatalogQueryRepository.Qualification.deploymentId", type = ResourceType.FIELD,
                labelPage = "tianquan-jianshen.permissions", labelKey = "field.deploymentId")
        @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
                plainRead = @PermissionGroup(codes = {"system:permission-catalog:read"}))
        String deploymentId,
            @PermissionResource(key = "tianquan-jianshen.field.registration.catalog.repository.PermissionCatalogQueryRepository.Qualification.expiresAt", type = ResourceType.FIELD,
                    labelPage = "tianquan-jianshen.permissions", labelKey = "field.expiresAt")
            @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
                    plainRead = @PermissionGroup(codes = {"system:permission-catalog:read"}))
            @com.fasterxml.jackson.annotation.JsonFormat(shape=com.fasterxml.jackson.annotation.JsonFormat.Shape.STRING) Instant expiresAt) { }
    public record Candidate(@PermissionResource(key = "tianquan-jianshen.field.registration.catalog.repository.PermissionCatalogQueryRepository.Candidate.producerVersion", type = ResourceType.FIELD,
                labelPage = "tianquan-jianshen.permissions", labelKey = "field.producerVersion")
        @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
                plainRead = @PermissionGroup(codes = {"system:permission-catalog:read"}))
        String producerVersion, @PermissionResource(key = "tianquan-jianshen.field.registration.catalog.repository.PermissionCatalogQueryRepository.Candidate.digests", type = ResourceType.FIELD,
                labelPage = "tianquan-jianshen.permissions", labelKey = "field.digests")
        @FieldPermissions(valueType = PermissionManifest.JsonFieldType.OBJECT,
                plainRead = @PermissionGroup(codes = {"system:permission-catalog:read"}))
        ManifestDigests digests, @PermissionResource(key = "tianquan-jianshen.field.registration.catalog.repository.PermissionCatalogQueryRepository.Candidate.state", type = ResourceType.FIELD,
                labelPage = "tianquan-jianshen.permissions", labelKey = "field.state")
        @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
                plainRead = @PermissionGroup(codes = {"system:permission-catalog:read"}))
        String state, @PermissionResource(key = "tianquan-jianshen.field.registration.catalog.repository.PermissionCatalogQueryRepository.Candidate.failureCode", type = ResourceType.FIELD,
                labelPage = "tianquan-jianshen.permissions", labelKey = "field.failureCode")
        @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
                plainRead = @PermissionGroup(codes = {"system:permission-catalog:read"}))
        String failureCode,
            @PermissionResource(key = "tianquan-jianshen.field.registration.catalog.repository.PermissionCatalogQueryRepository.Candidate.sourceOperationId", type = ResourceType.FIELD,
                    labelPage = "tianquan-jianshen.permissions", labelKey = "field.sourceOperationId")
            @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
                    plainRead = @PermissionGroup(codes = {"system:permission-catalog:read"}))
            String sourceOperationId, @PermissionResource(key = "tianquan-jianshen.field.registration.catalog.repository.PermissionCatalogQueryRepository.Candidate.repository", type = ResourceType.FIELD,
                labelPage = "tianquan-jianshen.permissions", labelKey = "field.repository")
        @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
                plainRead = @PermissionGroup(codes = {"system:permission-catalog:read"}))
        String repository, @PermissionResource(key = "tianquan-jianshen.field.registration.catalog.repository.PermissionCatalogQueryRepository.Candidate.commit", type = ResourceType.FIELD,
                labelPage = "tianquan-jianshen.permissions", labelKey = "field.commit")
        @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
                plainRead = @PermissionGroup(codes = {"system:permission-catalog:read"}))
        String commit, @PermissionResource(key = "tianquan-jianshen.field.registration.catalog.repository.PermissionCatalogQueryRepository.Candidate.buildId", type = ResourceType.FIELD,
                labelPage = "tianquan-jianshen.permissions", labelKey = "field.buildId")
        @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
                plainRead = @PermissionGroup(codes = {"system:permission-catalog:read"}))
        String buildId, @PermissionResource(key = "tianquan-jianshen.field.registration.catalog.repository.PermissionCatalogQueryRepository.Candidate.artifactVersion", type = ResourceType.FIELD,
                labelPage = "tianquan-jianshen.permissions", labelKey = "field.artifactVersion")
        @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
                plainRead = @PermissionGroup(codes = {"system:permission-catalog:read"}))
        String artifactVersion,
            @PermissionResource(key = "tianquan-jianshen.field.registration.catalog.repository.PermissionCatalogQueryRepository.Candidate.createdAt", type = ResourceType.FIELD,
                    labelPage = "tianquan-jianshen.permissions", labelKey = "field.createdAt")
            @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
                    plainRead = @PermissionGroup(codes = {"system:permission-catalog:read"}))
            @com.fasterxml.jackson.annotation.JsonFormat(shape=com.fasterxml.jackson.annotation.JsonFormat.Shape.STRING) Instant createdAt,
            @PermissionResource(key = "tianquan-jianshen.field.registration.catalog.repository.PermissionCatalogQueryRepository.Candidate.qualification", type = ResourceType.FIELD,
                    labelPage = "tianquan-jianshen.permissions", labelKey = "field.qualification")
            @FieldPermissions(valueType = PermissionManifest.JsonFieldType.OBJECT,
                    plainRead = @PermissionGroup(codes = {"system:permission-catalog:read"}))
            Qualification qualification) {
        public Candidate failedDelivery() {
            return new Candidate(producerVersion, digests, "FAILED", "METADATA_DELIVERY_EXHAUSTED", sourceOperationId,
                    repository, commit, buildId, artifactVersion, createdAt, qualification);
        }
    }
    public record StoredCandidate(Candidate value, long metadataRevision) { }

    private final EntityManager entityManager;
    private final PermissionCatalogJson json;

    public PermissionCatalogQueryRepository(EntityManager entityManager, PermissionCatalogJson json) {
        this.entityManager = entityManager;
        this.json = json;
    }

    public List<Producer> producers(CatalogScope scope) {
        List<?> rows = entityManager.createNativeQuery("""
                select p.producer_id,p.kind,p.expected_modules::text,p.current_revision,p.version,a.producer_version
                  from rbac3_catalog_producer p join rbac3_catalog_active_pointer h on h.catalog_scope_id=p.catalog_scope_id
                  left join rbac3_catalog_activation_producer a on a.catalog_scope_id=p.catalog_scope_id and a.activation_version=h.activation_version and a.producer_id=p.producer_id
                 where p.catalog_scope_id=:scope and p.enabled order by p.producer_id
                """).setParameter("scope", Long.parseLong(scope.catalogScopeId())).setMaxResults(257).getResultList();
        if (rows.size() > 256) throw new Rbac3RuleViolation("AUTH_RUNTIME_UNAVAILABLE");
        return rows.stream().map(value -> {
            Object[] row = (Object[]) value;
            return new Producer(row[0].toString(), row[1].toString(), json.strings(row[2].toString()), row[3].toString(), row[4].toString(),
                    row[5] == null ? null : row[5].toString());
        }).toList();
    }

    public List<StoredCandidate> candidates(CatalogScope scope, String producer, long beforeVersion, int limit, Instant now) {
        if (beforeVersion < 0 || limit < 1 || limit > 50) throw new IllegalArgumentException("invalid candidate pagination");
        List<?> rows = entityManager.createNativeQuery("""
                select m.producer_version,m.manifest_digest,m.policy_digest,m.metadata_digest,m.state,m.failure_code,m.source_operation_id,
                       m.repository,m.commit,m.build_id,m.artifact_version,m.created_at,m.version,
                       q.id,q.artifact_digest,q.deployment_id,q.expires_at
                  from rbac3_catalog_manifest m
                  left join lateral (
                    select candidate.id,candidate.artifact_digest,candidate.deployment_id,candidate.expires_at
                      from rbac3_catalog_deployment_qualification candidate
                     where candidate.catalog_scope_id=m.catalog_scope_id and candidate.producer_id=m.producer_id
                       and candidate.producer_version=m.producer_version and candidate.verified_at<=:now and candidate.expires_at>:now
                       and exists(select 1 from rbac3_catalog_service_grant g
                         where g.catalog_scope_id=candidate.catalog_scope_id and g.producer_id=candidate.producer_id and g.enabled
                           and g.issuer=candidate.trusted_issuer and g.client_id=candidate.trusted_client_id and g.resource_uri=candidate.trusted_resource
                           and g.capabilities @> '["QUALIFY_DEPLOYMENT"]'::jsonb
                           and g.allowed_source_refs @> jsonb_build_array(candidate.source_ref))
                     order by candidate.verified_at desc,candidate.id desc limit 1
                  ) q on true
                 where m.catalog_scope_id=:scope and m.producer_id=:producer and (:before=0 or m.producer_version<:before)
                 order by m.producer_version desc
                """).setParameter("scope", Long.parseLong(scope.catalogScopeId())).setParameter("producer", producer)
                .setParameter("before", beforeVersion).setParameter("now", now).setMaxResults(limit + 1).getResultList();
        return rows.stream().map(value -> {
            Object[] row = (Object[]) value;
            var qualification = row[13] == null ? null : new Qualification(row[13].toString(), row[14].toString(), row[15].toString(), instant(row[16]));
            var candidate = new Candidate(row[0].toString(), new ManifestDigests(row[2].toString(), row[3].toString(), row[1].toString()),
                    row[4].toString(), row[5] == null ? null : row[5].toString(), row[6].toString(), row[7].toString(), row[8].toString(),
                    row[9].toString(), row[10].toString(), instant(row[11]), qualification);
            return new StoredCandidate(candidate, ((Number) row[12]).longValue());
        }).toList();
    }

    private Instant instant(Object value) {
        if (value instanceof Instant instant) return instant;
        if (value instanceof OffsetDateTime timestamp) return timestamp.toInstant();
        if (value instanceof java.sql.Timestamp timestamp) return timestamp.toInstant();
        throw new IllegalArgumentException("unsupported database time");
    }
}
