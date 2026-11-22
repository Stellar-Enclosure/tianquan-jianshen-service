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

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

/** Immutable activation membership and a single CAS pointer; closure uses exact selected versions through the logical datasource. */
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

    private record PermissionIdentity(long id, String code) { }
    private record MessageIdentity(String page, String key) { }
    private record OwnedMessage(MessageIdentity message, String producer) { }

    public void requireReferenceClosure(CatalogActivationRequest request) {
        // Keep JSON expansion out of routed SQL. ShardingSphere binds ordinary table projections,
        // while the shared contract reader validates the selected immutable FULL manifests.
        Map<String, Object> parameters = new LinkedHashMap<>();
        parameters.put("scope", Long.parseLong(request.target().catalogScopeId()));
        for (int index = 0; index < request.producers().size(); index++) {
            var selection = request.producers().get(index);
            parameters.put("producer" + index, selection.producerId());
            parameters.put("revision" + index, Long.parseLong(selection.producerVersion()));
        }
        String selection = IntStream.range(0, request.producers().size())
                .mapToObj(index -> "(v.producer_id=:producer" + index + " and v.producer_version=:revision" + index + ")")
                .collect(Collectors.joining(" or "));
        String selected = " where v.catalog_scope_id=:scope and (" + selection + ")";
        List<?> manifestRows = query("select v.canonical_manifest::text from rbac3_catalog_manifest v" + selected, parameters).getResultList();
        List<PermissionManifest> manifests = manifestRows.stream().map(value -> json.manifest(value.toString())).toList();
        requireClosure(manifests.size() == request.producers().size());
        requireClosure(manifests.stream().allMatch(manifest -> manifest.producer().snapshotMode() == PermissionManifest.SnapshotMode.FULL));

        Map<String, ResourceType> resources = new HashMap<>();
        List<PermissionManifest.I18nReference> labels = new ArrayList<>();
        List<?> resourceRows = query("""
                select v.producer_id,v.registration_key,v.resource_type,v.i18n_json::text,g.governance_state,g.owner_producer_id
                  from rbac3_catalog_resource_version v join rbac3_catalog_resource g
                    on g.catalog_scope_id=v.catalog_scope_id and g.id=v.resource_id
                """ + selected, parameters).getResultList();
        for (Object value : resourceRows) {
            Object[] row = (Object[]) value;
            requireClosure(!"RETIRED".equals(row[4]) && row[0].equals(row[5]));
            resources.put(row[1].toString(), ResourceType.valueOf(row[2].toString()));
            labels.add(json.read(row[3].toString(), PermissionManifest.I18nReference.class));
        }
        Set<PermissionIdentity> permissions = new HashSet<>();
        List<?> permissionRows = query("""
                select v.producer_id,v.permission_id,v.permission_code,v.i18n_json::text,g.governance_state,g.owner_producer_id
                  from rbac3_catalog_permission_version v join rbac3_catalog_permission g
                    on g.catalog_scope_id=v.catalog_scope_id and g.id=v.permission_id
                """ + selected, parameters).getResultList();
        for (Object value : permissionRows) {
            Object[] row = (Object[]) value;
            requireClosure(!"RETIRED".equals(row[4]) && row[0].equals(row[5]));
            permissions.add(new PermissionIdentity(((Number) row[1]).longValue(), row[2].toString()));
            labels.add(json.read(row[3].toString(), PermissionManifest.I18nReference.class));
        }
        Set<String> codes = permissions.stream().map(PermissionIdentity::code).collect(Collectors.toSet());
        for (PermissionManifest manifest : manifests) {
            requireClosure(codes.containsAll(manifest.permissionReferences()));
            for (var reference : manifest.resourceReferences()) {
                ResourceType type = resources.get(reference.key());
                requireClosure(type != null);
                if (Set.of("FORM_FIELD", "TABLE_FIELD", "DETAIL_FIELD").contains(reference.usage())) requireClosure(type == ResourceType.FIELD);
                if ("CALLS".equals(reference.usage())) requireClosure(type == ResourceType.API);
            }
        }
        List<?> requirements = query("select v.permission_id,v.permission_code from rbac3_catalog_resource_requirement v" + selected, parameters).getResultList();
        for (Object value : requirements) {
            Object[] row = (Object[]) value;
            requireClosure(row[0] != null && permissions.contains(new PermissionIdentity(((Number) row[0]).longValue(), row[1].toString())));
        }

        Set<OwnedMessage> declaredMessages = new HashSet<>();
        for (PermissionManifest manifest : manifests) {
            for (var message : manifest.messages()) {
                declaredMessages.add(new OwnedMessage(new MessageIdentity(message.pageCode(), message.key()), manifest.producer().id()));
            }
        }
        Set<MessageIdentity> messages = new HashSet<>();
        List<?> owners = query("""
                select page_code,message_key,owner_producer_id from rbac3_catalog_message_owner
                 where catalog_scope_id=:scope and lifecycle='ACTIVE' and owner_producer_id in (:producers)
                """, Map.of("scope", parameters.get("scope"), "producers", request.producers().stream().map(CatalogActivationRequest.Selection::producerId).toList()))
                .getResultList();
        for (Object value : owners) {
            Object[] row = (Object[]) value;
            var message = new MessageIdentity(row[0].toString(), row[1].toString());
            if (declaredMessages.contains(new OwnedMessage(message, row[2].toString()))) messages.add(message);
        }
        for (var label : labels) {
            requireClosure(label.keys().stream().allMatch(key -> messages.contains(new MessageIdentity(label.pageCode(), key))));
        }
    }

    private void requireClosure(boolean valid) {
        if (!valid) throw new Rbac3RuleViolation("RESOURCE_MANIFEST_CONFLICT");
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
