package top.egon.cola.platform.tianquan.jianshen.admin.registration.catalog.repository;

import top.egon.cola.platform.tianquan.jianshen.contract.permission.annotation.PermissionResource;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.ResourceAccess;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.ResourceType;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.PermissionManifest;

import jakarta.persistence.EntityManager;
import jakarta.persistence.Query;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import top.egon.cola.platform.tianquan.jianshen.admin.registration.catalog.domain.convertor.PermissionCatalogJson;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.ActivationDescriptor;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.CatalogActivationRequest;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.CatalogScope;
import top.egon.cola.platform.tianquan.jianshen.core.rule.Rbac3RuleViolation;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/** Immutable activation membership and a single CAS pointer; closure checks stay in bounded SQL projections. */
@Repository
@Transactional(propagation = Propagation.MANDATORY)
public class PermissionCatalogActivationRepository {
    public record Operation(String requestDigest, ActivationDescriptor descriptor) { }
    public record History(@PermissionResource(key = "tianquan-jianshen.field.registration.catalog.repository.PermissionCatalogActivationRepository.History.currentRevision", type = ResourceType.FIELD,
                labelPage = "tianquan-jianshen.permissions", labelKey = "field.currentRevision", access = ResourceAccess.PUBLIC,
                allowedPrincipals = {PermissionManifest.PrincipalType.USER, PermissionManifest.PrincipalType.SERVICE}, oauthScopes = {"tianquan-jianshen:permission-catalog:read"})
        String currentRevision, @PermissionResource(key = "tianquan-jianshen.field.registration.catalog.repository.PermissionCatalogActivationRepository.History.versions", type = ResourceType.FIELD,
                labelPage = "tianquan-jianshen.permissions", labelKey = "field.versions", access = ResourceAccess.PUBLIC,
                allowedPrincipals = {PermissionManifest.PrincipalType.USER, PermissionManifest.PrincipalType.SERVICE}, oauthScopes = {"tianquan-jianshen:permission-catalog:read"})
        List<ActivationDescriptor> versions) {
        public History { versions = List.copyOf(versions); }
    }

    private final EntityManager entityManager;
    private final PermissionCatalogJson json;

    public PermissionCatalogActivationRepository(EntityManager entityManager, PermissionCatalogJson json) {
        this.entityManager = entityManager;
        this.json = json;
    }

    public Optional<Operation> operation(CatalogScope scope, String operation) {
        var rows = query("""
                select request_digest,descriptor_json::text from rbac3_catalog_activation
                 where catalog_scope_id=:scope and operation_id=:operation
                """, Map.of("scope", Long.parseLong(scope.catalogScopeId()), "operation", operation)).getResultList();
        if (rows.isEmpty()) return Optional.empty();
        Object[] row = (Object[]) rows.getFirst();
        return Optional.of(new Operation(row[0].toString(), descriptor(row[1].toString(), scope)));
    }

    public ActivationDescriptor require(CatalogScope scope, long version) {
        var rows = query("""
                select descriptor_json::text from rbac3_catalog_activation where catalog_scope_id=:scope and activation_version=:version
                """, Map.of("scope", Long.parseLong(scope.catalogScopeId()), "version", version)).getResultList();
        if (rows.size() != 1) throw new Rbac3RuleViolation("RESOURCE_NOT_FOUND");
        return descriptor(rows.getFirst().toString(), scope);
    }

    public History history(CatalogScope scope, long beforeVersion, int limit) {
        if (beforeVersion < 0 || limit < 1 || limit > 50) throw new IllegalArgumentException("invalid activation pagination");
        long current = ((Number) query("select revision from rbac3_catalog_active_pointer where catalog_scope_id=:scope",
                Map.of("scope", Long.parseLong(scope.catalogScopeId()))).getSingleResult()).longValue();
        var rows = query("""
                select descriptor_json::text from rbac3_catalog_activation where catalog_scope_id=:scope
                   and (:before=0 or activation_version<:before) order by activation_version desc
                """, Map.of("scope", Long.parseLong(scope.catalogScopeId()), "before", beforeVersion)).setMaxResults(limit).getResultList();
        return new History(Long.toString(current), rows.stream().map(value -> descriptor(value.toString(), scope)).toList());
    }

    public void requireComplete(CatalogActivationRequest request) {
        List<?> enabled = query("select producer_id from rbac3_catalog_producer where catalog_scope_id=:scope and enabled order by producer_id",
                Map.of("scope", Long.parseLong(request.target().catalogScopeId()))).setMaxResults(257).getResultList();
        var selected = request.producers().stream().map(CatalogActivationRequest.Selection::producerId).collect(java.util.stream.Collectors.toSet());
        if (enabled.size() != selected.size() || !selected.equals(enabled.stream().map(Object::toString).collect(java.util.stream.Collectors.toSet()))) {
            throw new Rbac3RuleViolation("RESOURCE_MANIFEST_CONFLICT");
        }
    }

    public void requireReferenceClosure(CatalogActivationRequest request) {
        // Only the selected version rows participate. A known but absent old definition cannot satisfy a reference.
        String sql = """
                with selected as (
                    select x."producerId" producer_id, cast(x."producerVersion" as bigint) producer_version
                      from jsonb_to_recordset(cast(:selection as jsonb)) x("producerId" text,"producerVersion" text)
                ), manifests as (
                    select m.* from rbac3_catalog_manifest m join selected s using(producer_id,producer_version)
                     where m.catalog_scope_id=:scope
                ), resources as (
                    select r.* from rbac3_catalog_resource_version r join selected s using(producer_id,producer_version)
                     where r.catalog_scope_id=:scope
                ), permissions as (
                    select p.* from rbac3_catalog_permission_version p join selected s using(producer_id,producer_version)
                     where p.catalog_scope_id=:scope
                ), messages as (
                    select m.producer_id,j->>'pageCode' page_code,j->>'key' message_key
                      from manifests m cross join lateral jsonb_array_elements(m.canonical_manifest->'messages') j
                ), i18n as (
                    select i18n_json i from resources union all select i18n_json from permissions
                )
                select exists (
                    select 1 from resources r join rbac3_catalog_resource g on g.catalog_scope_id=r.catalog_scope_id and g.id=r.resource_id
                     where g.governance_state='RETIRED' or g.owner_producer_id<>r.producer_id
                    union all
                    select 1 from permissions p join rbac3_catalog_permission g on g.catalog_scope_id=p.catalog_scope_id and g.id=p.permission_id
                     where g.governance_state='RETIRED' or g.owner_producer_id<>p.producer_id
                    union all
                    select 1 from manifests m cross join lateral jsonb_array_elements_text(m.canonical_manifest->'permissionReferences') ref
                     where not exists(select 1 from permissions p where p.permission_code=ref)
                    union all
                    select 1 from manifests m cross join lateral jsonb_array_elements(m.canonical_manifest->'resourceReferences') ref
                     where not exists(select 1 from resources r where r.registration_key=ref->>'key'
                         and (ref->>'usage' not in ('FORM_FIELD','TABLE_FIELD','DETAIL_FIELD') or r.resource_type='FIELD')
                         and (ref->>'usage'<>'CALLS' or r.resource_type='API'))
                    union all
                    select 1 from rbac3_catalog_resource_requirement q join selected s using(producer_id,producer_version)
                     where q.catalog_scope_id=:scope and not exists(select 1 from permissions p where p.permission_code=q.permission_code
                         and p.permission_id=q.permission_id)
                    union all
                    select 1 from i18n cross join lateral jsonb_each_text(i) entry
                     where entry.key<>'pageCode' and entry.value is not null and not exists (
                         select 1 from messages msg join rbac3_catalog_message_owner o
                           on o.catalog_scope_id=:scope and o.page_code=msg.page_code and o.message_key=msg.message_key
                          and o.owner_producer_id=msg.producer_id and o.lifecycle='ACTIVE'
                          where msg.page_code=i->>'pageCode' and msg.message_key=entry.value)
                )
                """;
        Object invalid = query(sql, Map.of("scope", Long.parseLong(request.target().catalogScopeId()),
                "selection", json.write(request.producers().stream().map(CatalogActivationRequest.Selection::toMap).toList()))).getSingleResult();
        if (!Boolean.FALSE.equals(invalid)) throw new Rbac3RuleViolation("RESOURCE_MANIFEST_CONFLICT");
    }

    public void save(CatalogActivationRequest request, ActivationDescriptor descriptor, String actor) {
        Map<String, Object> values = new LinkedHashMap<>();
        values.put("scope", Long.parseLong(request.target().catalogScopeId()));
        values.put("version", Long.parseLong(descriptor.activationVersion()));
        values.put("operation", request.operationId());
        values.put("expected", Long.parseLong(request.expectedActiveRevision()));
        values.put("requestDigest", request.requestDigest());
        values.put("descriptor", descriptor.canonicalize());
        values.put("descriptorDigest", descriptor.digest());
        values.put("count", descriptor.producers().size());
        values.put("policy", Long.parseLong(descriptor.policyVersion()));
        values.put("now", descriptor.createdAt());
        values.put("actor", actor);
        query("""
                insert into rbac3_catalog_activation
                    (catalog_scope_id,activation_version,operation_id,expected_active_revision,request_digest,descriptor_json,
                     descriptor_digest,producer_count,policy_version,created_at,created_by)
                values (:scope,:version,:operation,:expected,:requestDigest,cast(:descriptor as jsonb),:descriptorDigest,:count,:policy,:now,:actor)
                """, values).executeUpdate();
        for (var producer : descriptor.producers()) {
            Map<String, Object> member = new LinkedHashMap<>();
            member.put("scope", values.get("scope"));
            member.put("version", values.get("version"));
            member.put("producer", producer.producerId());
            member.put("revision", Long.parseLong(producer.producerVersion()));
            member.put("manifest", producer.digests().manifestDigest());
            member.put("policy", producer.digests().policyDigest());
            member.put("metadata", producer.digests().metadataDigest());
            member.put("source", producer.sourceVersion());
            member.put("qualification", Long.parseLong(producer.qualificationId()));
            query("""
                    insert into rbac3_catalog_activation_producer (catalog_scope_id,activation_version,producer_id,producer_version,
                        manifest_digest,policy_digest,metadata_digest,source_version,qualification_id)
                    values (:scope,:version,:producer,:revision,:manifest,:policy,:metadata,:source,:qualification)
                    """, member).executeUpdate();
        }
        int changed = query("""
                update rbac3_catalog_active_pointer set activation_version=:version,revision=:version,policy_version=:policy,
                    version=version+1,updated_at=:now,updated_by=:actor where catalog_scope_id=:scope and revision=:expected
                """, Map.of("scope", values.get("scope"), "version", values.get("version"), "policy", values.get("policy"),
                "now", values.get("now"), "actor", actor, "expected", values.get("expected"))).executeUpdate();
        if (changed != 1) throw new Rbac3RuleViolation("RESOURCE_VERSION_CONFLICT");
    }

    private ActivationDescriptor descriptor(String value, CatalogScope scope) {
        var descriptor = json.read(value, ActivationDescriptor.class);
        if (!scope.equals(descriptor.scope())) throw new Rbac3RuleViolation("RESOURCE_MANIFEST_CONFLICT");
        return descriptor;
    }

    private Query query(String sql, Map<String, Object> values) {
        Query query = entityManager.createNativeQuery(sql);
        values.forEach(query::setParameter);
        return query;
    }
}
