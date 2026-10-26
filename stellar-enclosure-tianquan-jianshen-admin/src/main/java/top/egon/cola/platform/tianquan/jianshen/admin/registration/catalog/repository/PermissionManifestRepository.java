package top.egon.cola.platform.tianquan.jianshen.admin.registration.catalog.repository;

import jakarta.persistence.EntityManager;
import jakarta.persistence.Query;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import top.egon.cola.platform.tianquan.jianshen.admin.registration.catalog.domain.PermissionRegistrationPlan;
import top.egon.cola.platform.tianquan.jianshen.admin.registration.catalog.domain.convertor.PermissionCatalogJson;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.CatalogScope;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.ManifestDigests;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.ManifestRegistrationReceipt;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.ManifestRegistrationRequest;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.PermissionManifest;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.SourceImportRequest;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.SourceImportReceipt;
import top.egon.cola.platform.tianquan.jianshen.core.registration.PermissionManifestDiff;
import top.egon.cola.platform.tianquan.jianshen.core.rule.Rbac3RuleViolation;

import java.sql.Timestamp;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.TreeMap;
import java.util.stream.Collectors;

/** Immutable candidate, plan and original-operation storage. The service owns the transaction. */
@Repository
@Transactional(propagation = Propagation.MANDATORY)
public class PermissionManifestRepository {

    public record StoredManifest(long producerVersion, PermissionManifest manifest, ManifestDigests digests,
                                 String sourceOperationId, String state, String failureCode, long metadataRevision) { }

    public record StoredOperation(String requestDigest, ManifestRegistrationReceipt receipt) { }

    private final EntityManager entityManager;
    private final PermissionCatalogJson json;

    public PermissionManifestRepository(EntityManager entityManager, PermissionCatalogJson json) {
        this.entityManager = entityManager;
        this.json = json;
    }

    public void savePlan(PermissionRegistrationPlan plan) {
        Map<String, Object> parameters = scoped(plan.request().target(), plan.request().manifest().producer().id());
        parameters.put("id", plan.id());
        parameters.put("producerRevision", Long.parseLong(plan.request().expectedProducerRevision()));
        parameters.put("activeRevision", Long.parseLong(plan.request().expectedActiveRevision()));
        parameters.put("ownerVersion", plan.ownerVersion());
        parameters.put("grantId", plan.serviceGrantId());
        parameters.put("grantVersion", plan.serviceGrantVersion());
        parameters.put("manifestDigest", plan.digests().manifestDigest());
        parameters.put("policyDigest", plan.digests().policyDigest());
        parameters.put("metadataDigest", plan.digests().metadataDigest());
        parameters.put("requestDigest", plan.request().requestDigest());
        parameters.put("manifest", json.write(plan.request().manifest()));
        parameters.put("diff", json.write(plan.diff()));
        parameters.put("expansion", plan.diff().authorizationExpansion());
        parameters.put("expires", plan.expiresAt());
        parameters.put("created", plan.createdAt());
        parameters.put("actor", plan.createdBy());
        query("""
                insert into rbac3_catalog_registration_plan
                    (id,catalog_scope_id,producer_id,expected_producer_revision,expected_active_revision,owner_version,
                     service_grant_id,service_grant_version,manifest_digest,policy_digest,metadata_digest,request_digest,
                     canonical_manifest,diff_json,authorization_expansion,expires_at,created_at,created_by)
                values (:id,:scope,:producer,:producerRevision,:activeRevision,:ownerVersion,:grantId,:grantVersion,
                        :manifestDigest,:policyDigest,:metadataDigest,:requestDigest,cast(:manifest as jsonb),
                        cast(:diff as jsonb),:expansion,:expires,:created,:actor)
                """, parameters).executeUpdate();
    }

    public Optional<PermissionRegistrationPlan> findPlan(CatalogScope target, String producer, long id) {
        Map<String, Object> parameters = scoped(target, producer);
        parameters.put("id", id);
        List<?> rows = query("""
                select canonical_manifest::text,expected_producer_revision,expected_active_revision,owner_version,
                       service_grant_id,service_grant_version,manifest_digest,policy_digest,metadata_digest,diff_json::text,
                       expires_at,created_at,created_by,request_digest
                  from rbac3_catalog_registration_plan where catalog_scope_id=:scope and producer_id=:producer and id=:id
                """, parameters).getResultList();
        if (rows.isEmpty()) return Optional.empty();
        Object[] row = (Object[]) rows.getFirst();
        var request = new ManifestRegistrationRequest.Plan(target, json.manifest(row[0].toString()), row[1].toString(), row[2].toString());
        if (!request.requestDigest().equals(row[13])) throw new Rbac3RuleViolation("RESOURCE_MANIFEST_INVALID");
        return Optional.of(new PermissionRegistrationPlan(id, request, number(row[3]), number(row[4]), number(row[5]),
                new ManifestDigests(row[7].toString(), row[8].toString(), row[6].toString()),
                json.read(row[9].toString(), PermissionManifestDiff.Result.class), instant(row[10]), instant(row[11]), row[12].toString()));
    }

    public Optional<PermissionManifest> activeManifest(CatalogScope target, String producer) {
        List<?> rows = query("""
                select m.canonical_manifest::text from rbac3_catalog_active_pointer p
                  join rbac3_catalog_activation_producer a on a.catalog_scope_id=p.catalog_scope_id and a.activation_version=p.activation_version
                  join rbac3_catalog_manifest m on m.catalog_scope_id=a.catalog_scope_id and m.producer_id=a.producer_id and m.producer_version=a.producer_version
                 where p.catalog_scope_id=:scope and a.producer_id=:producer
                """, scoped(target, producer)).getResultList();
        return rows.isEmpty() ? Optional.empty() : Optional.of(json.manifest(rows.getFirst().toString()));
    }

    public Set<String> grantedCodes(CatalogScope target) {
        List<?> rows = query("""
                select distinct p.permission_code from rbac3_catalog_role_permission g
                  join rbac3_catalog_permission p on p.catalog_scope_id=g.catalog_scope_id and p.id=g.permission_id
                  join rbac3_catalog_role_binding b on b.catalog_scope_id=g.catalog_scope_id and b.role_id=g.role_id
                 where g.catalog_scope_id=:scope and b.enabled and g.status='ACTIVE' and p.governance_state='ACTIVE'
                """, Map.of("scope", Long.parseLong(target.catalogScopeId()))).getResultList();
        // Include future and currently unassigned grants: capability expansion must not be hidden by timing.
        return rows.stream().map(Object::toString).collect(Collectors.toUnmodifiableSet());
    }

    public Optional<StoredManifest> findByDigest(CatalogScope target, String producer, String digest) {
        Map<String, Object> parameters = scoped(target, producer);
        parameters.put("digest", digest);
        return manifest(query("""
                select producer_version,canonical_manifest::text,manifest_digest,policy_digest,metadata_digest,source_operation_id,state,failure_code,version
                  from rbac3_catalog_manifest where catalog_scope_id=:scope and producer_id=:producer and manifest_digest=:digest
                """, parameters).getResultList());
    }

    public Optional<StoredManifest> findVersion(CatalogScope target, String producer, long revision) {
        Map<String, Object> parameters = scoped(target, producer);
        parameters.put("revision", revision);
        return manifest(query("""
                select producer_version,canonical_manifest::text,manifest_digest,policy_digest,metadata_digest,source_operation_id,state,failure_code,version
                  from rbac3_catalog_manifest where catalog_scope_id=:scope and producer_id=:producer and producer_version=:revision
                """, parameters).getResultList());
    }

    private Optional<StoredManifest> manifest(List<?> rows) {
        if (rows.isEmpty()) return Optional.empty();
        Object[] row = (Object[]) rows.getFirst();
        return Optional.of(new StoredManifest(number(row[0]), json.manifest(row[1].toString()),
                new ManifestDigests(row[3].toString(), row[4].toString(), row[2].toString()), row[5].toString(), row[6].toString(),
                row[7] == null ? null : row[7].toString(), number(row[8])));
    }

    public Optional<StoredOperation> findOperation(CatalogScope target, String producer, String operationId) {
        Map<String, Object> parameters = scoped(target, producer);
        parameters.put("operation", operationId);
        List<?> rows = query("""
                select request_digest,original_receipt_json::text from rbac3_catalog_registration_operation
                 where catalog_scope_id=:scope and producer_id=:producer and operation_id=:operation
                """, parameters).getResultList();
        if (rows.isEmpty()) return Optional.empty();
        Object[] row = (Object[]) rows.getFirst();
        return Optional.of(new StoredOperation(row[0].toString(), json.read(row[1].toString(), ManifestRegistrationReceipt.class)));
    }

    public void saveManifest(CatalogScope target, PermissionManifest manifest, ManifestDigests digests, long revision,
                             String sourceOperation, PermissionManifestDiff.Result diff, String actor, Instant now) {
        Map<String, Object> parameters = scoped(target, manifest.producer().id());
        parameters.put("revision", revision);
        parameters.put("manifestDigest", digests.manifestDigest());
        parameters.put("policyDigest", digests.policyDigest());
        parameters.put("metadataDigest", digests.metadataDigest());
        parameters.put("manifest", json.write(manifest));
        parameters.put("operation", sourceOperation);
        parameters.put("repository", manifest.artifact().repository());
        parameters.put("commit", manifest.artifact().commit());
        parameters.put("build", manifest.artifact().buildId());
        parameters.put("artifactVersion", manifest.artifact().version());
        parameters.put("resourceCount", manifest.resources().size());
        parameters.put("permissionCount", manifest.permissionDefinitions().size());
        parameters.put("messageCount", manifest.messages().size());
        parameters.put("diff", json.write(diff));
        parameters.put("actor", actor);
        parameters.put("now", now);
        query("""
                insert into rbac3_catalog_manifest
                    (catalog_scope_id,producer_id,producer_version,manifest_digest,policy_digest,metadata_digest,canonical_manifest,
                     state,source_operation_id,repository,commit,build_id,artifact_version,resource_count,permission_count,message_count,
                     diff_json,created_at,created_by,updated_at)
                values (:scope,:producer,:revision,:manifestDigest,:policyDigest,:metadataDigest,cast(:manifest as jsonb),
                        'REGISTERED',:operation,:repository,:commit,:build,:artifactVersion,:resourceCount,:permissionCount,:messageCount,
                        cast(:diff as jsonb),:now,:actor,:now)
                """, parameters).executeUpdate();
    }

    public void seal(CatalogScope target, String producer, long revision, Instant now) {
        Map<String, Object> parameters = scoped(target, producer);
        parameters.put("revision", revision);
        parameters.put("now", now);
        int changed = query("""
                update rbac3_catalog_manifest set state='METADATA_PENDING',version=version+1,updated_at=:now
                 where catalog_scope_id=:scope and producer_id=:producer and producer_version=:revision and state='REGISTERED'
                """, parameters).executeUpdate();
        if (changed != 1) throw new Rbac3RuleViolation("RESOURCE_VERSION_CONFLICT");
    }

    public void saveOperation(ManifestRegistrationRequest.Apply request, ManifestRegistrationReceipt receipt) {
        Map<String, Object> parameters = scoped(request.target(), request.producerId());
        parameters.put("operation", request.operationId());
        parameters.put("plan", Long.parseLong(request.planId()));
        parameters.put("requestDigest", request.requestDigest());
        parameters.put("manifestDigest", receipt.digests().manifestDigest());
        parameters.put("revision", Long.parseLong(receipt.producerVersion()));
        parameters.put("receipt", json.write(receipt));
        parameters.put("now", receipt.registeredAt());
        parameters.put("actor", "service-registration");
        query("""
                insert into rbac3_catalog_registration_operation
                    (catalog_scope_id,producer_id,operation_id,plan_id,request_digest,manifest_digest,producer_version,original_receipt_json,created_at,created_by)
                values (:scope,:producer,:operation,:plan,:requestDigest,:manifestDigest,:revision,cast(:receipt as jsonb),:now,:actor)
                """, parameters).executeUpdate();
    }

    public SourceImportRequest sourceImport(CatalogScope target, String producer, long revision) {
        StoredManifest stored = findVersion(target, producer, revision).orElseThrow(() -> new Rbac3RuleViolation("RESOURCE_NOT_FOUND"));
        Map<String, Object> parameters = scoped(target, producer);
        parameters.put("revision", revision);
        Map<String, String> resourceIds = ids(query("""
                select registration_key,resource_id from rbac3_catalog_resource_version
                 where catalog_scope_id=:scope and producer_id=:producer and producer_version=:revision
                """, parameters).getResultList());
        Map<String, String> permissionIds = ids(query("""
                select permission_code,permission_id from rbac3_catalog_permission_version
                 where catalog_scope_id=:scope and producer_id=:producer and producer_version=:revision
                """, parameters).getResultList());
        return new SourceImportRequest(stored.sourceOperationId(), target, producer, Long.toString(revision), stored.digests().manifestDigest(),
                stored.manifest(), stored.digests(), resourceIds, permissionIds);
    }

    public Optional<SourceImportReceipt> sourceReceipt(CatalogScope target, String producer, long revision) {
        Map<String, Object> parameters = scoped(target, producer);
        parameters.put("revision", revision);
        List<?> rows = query("""
                select receipt_json::text from rbac3_catalog_source_receipt
                 where catalog_scope_id=:scope and producer_id=:producer and producer_version=:revision
                """, parameters).getResultList();
        return rows.isEmpty() ? Optional.empty() : Optional.of(json.read(rows.getFirst().toString(), SourceImportReceipt.class));
    }

    public void saveSourceReceipt(SourceImportReceipt receipt, Instant now) {
        Map<String, Object> parameters = scoped(receipt.scope(), receipt.producerId());
        parameters.put("revision", Long.parseLong(receipt.producerVersion()));
        parameters.put("operation", receipt.operationId());
        parameters.put("receiptId", receipt.receiptId());
        parameters.put("sourceVersion", receipt.sourceVersion());
        parameters.put("manifestDigest", receipt.digests().manifestDigest());
        parameters.put("policyDigest", receipt.digests().policyDigest());
        parameters.put("metadataDigest", receipt.digests().metadataDigest());
        parameters.put("projectionDigest", receipt.projectionDigest());
        parameters.put("receipt", json.write(receipt));
        parameters.put("now", now);
        query("""
                insert into rbac3_catalog_source_receipt
                    (catalog_scope_id,producer_id,producer_version,source_operation_id,receipt_id,source_version,
                     manifest_digest,policy_digest,metadata_digest,projection_digest,receipt_json,received_at)
                values (:scope,:producer,:revision,:operation,:receiptId,:sourceVersion,:manifestDigest,:policyDigest,:metadataDigest,
                        :projectionDigest,cast(:receipt as jsonb),:now)
                """, parameters).executeUpdate();
    }

    public void markReady(SourceImportReceipt receipt, Instant now) {
        Map<String, Object> parameters = scoped(receipt.scope(), receipt.producerId());
        parameters.put("revision", Long.parseLong(receipt.producerVersion()));
        parameters.put("receipt", receipt.receiptId());
        parameters.put("now", now);
        int changed = query("""
                update rbac3_catalog_manifest set state='READY',metadata_receipt_id=:receipt,failure_code=null,version=version+1,updated_at=:now
                 where catalog_scope_id=:scope and producer_id=:producer and producer_version=:revision and state='METADATA_PENDING'
                """, parameters).executeUpdate();
        if (changed != 1) throw new Rbac3RuleViolation("RESOURCE_VERSION_CONFLICT");
    }

    public boolean markFailed(SourceImportRequest source, long metadataRevision, String code, Instant now) {
        Map<String, Object> parameters = scoped(source.scope(), source.producerId());
        parameters.put("revision", Long.parseLong(source.producerVersion()));
        parameters.put("failure", code);
        parameters.put("metadataRevision", metadataRevision);
        parameters.put("now", now);
        return query("""
                update rbac3_catalog_manifest set state='FAILED',failure_code=:failure,version=version+1,updated_at=:now
                 where catalog_scope_id=:scope and producer_id=:producer and producer_version=:revision and state='METADATA_PENDING' and version=:metadataRevision
                """, parameters).executeUpdate() == 1;
    }

    public long restartMetadata(SourceImportRequest source, long expectedVersion, Instant now) {
        Map<String, Object> parameters = scoped(source.scope(), source.producerId());
        parameters.put("revision", Long.parseLong(source.producerVersion()));
        parameters.put("expectedVersion", expectedVersion);
        parameters.put("now", now);
        int changed = query("""
                update rbac3_catalog_manifest set state='METADATA_PENDING',failure_code=null,version=version+1,updated_at=:now
                 where catalog_scope_id=:scope and producer_id=:producer and producer_version=:revision
                   and state='FAILED' and version=:expectedVersion
                """, parameters).executeUpdate();
        if (changed != 1) throw new Rbac3RuleViolation("RESOURCE_VERSION_CONFLICT");
        return Math.addExact(expectedVersion, 1);
    }

    public void resumeMetadata(SourceImportRequest source, Instant now) {
        Map<String, Object> parameters = scoped(source.scope(), source.producerId());
        parameters.put("revision", Long.parseLong(source.producerVersion()));
        parameters.put("now", now);
        query("""
                update rbac3_catalog_manifest set state='METADATA_PENDING',failure_code=null,version=version+1,updated_at=:now
                 where catalog_scope_id=:scope and producer_id=:producer and producer_version=:revision and state='FAILED'
                """, parameters).executeUpdate();
    }

    private Map<String, String> ids(List<?> rows) {
        Map<String, String> result = new TreeMap<>();
        for (Object value : rows) {
            Object[] row = (Object[]) value;
            result.put(row[0].toString(), row[1].toString());
        }
        return Map.copyOf(result);
    }

    private Map<String, Object> scoped(CatalogScope target, String producer) {
        Map<String, Object> parameters = new LinkedHashMap<>();
        parameters.put("scope", Long.parseLong(target.catalogScopeId()));
        parameters.put("producer", producer);
        return parameters;
    }

    private Query query(String sql, Map<String, Object> parameters) {
        Query query = entityManager.createNativeQuery(sql);
        parameters.forEach(query::setParameter);
        return query;
    }

    private long number(Object value) {
        return ((Number) value).longValue();
    }

    private Instant instant(Object value) {
        if (value instanceof Instant instant) return instant;
        if (value instanceof OffsetDateTime date) return date.toInstant();
        if (value instanceof Timestamp timestamp) return timestamp.toInstant();
        throw new IllegalStateException("unexpected PostgreSQL timestamp representation");
    }
}
