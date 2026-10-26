package top.egon.cola.platform.tianquan.jianshen.admin.registration.catalog.repository;

import jakarta.persistence.EntityManager;
import jakarta.persistence.Query;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import top.egon.cola.component.common.id.snowflake.SnowflakeIdGenerator;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.CanonicalJson;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.CatalogScope;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.PermissionManifest;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.PermissionManifestCanonicalizer;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.PermissionRequirement;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.ResourceAccess;
import top.egon.cola.platform.tianquan.jianshen.core.rule.Rbac3RuleViolation;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.function.Function;
import java.util.stream.Collectors;

/** Stable IDs and append-only definitions; CI never updates centre governance or role grants. */
@Repository
@Transactional(propagation = Propagation.MANDATORY)
public class PermissionCatalogDefinitionRepository {

    public record Identity(String id, String key, String owner, String state, String semantics) { }

    public record Identities(Map<String, Identity> resources, Map<String, Identity> permissions, Map<String, Identity> messages) {
        public Identities {
            resources = Map.copyOf(resources);
            permissions = Map.copyOf(permissions);
            messages = Map.copyOf(messages);
        }
    }

    public record AssignedIds(Map<String, String> resources, Map<String, String> permissions) {
        public AssignedIds {
            resources = Map.copyOf(resources);
            permissions = Map.copyOf(permissions);
        }
    }

    private final EntityManager entityManager;
    private final PermissionManifestCanonicalizer canonicalizer = new PermissionManifestCanonicalizer();

    public PermissionCatalogDefinitionRepository(EntityManager entityManager) {
        this.entityManager = entityManager;
    }

    public Identities load(CatalogScope scope) {
        Map<String, Object> params = Map.of("scope", Long.parseLong(scope.catalogScopeId()));
        Map<String, Identity> resources = identities(query("""
                select id,registration_key,owner_producer_id,governance_state,resource_type
                  from rbac3_catalog_resource where catalog_scope_id=:scope
                """, params).getResultList());
        Map<String, Identity> permissions = identities(query("""
                select id,permission_code,owner_producer_id,governance_state,meaning
                  from rbac3_catalog_permission where catalog_scope_id=:scope
                """, params).getResultList());
        Map<String, Identity> messages = identities(query("""
                select page_code || '/' || message_key,page_code || '/' || message_key,owner_producer_id,lifecycle,''
                  from rbac3_catalog_message_owner where catalog_scope_id=:scope
                """, params).getResultList());
        return new Identities(resources, permissions, messages);
    }

    public void validate(PermissionCatalogScopeRepository.Owner owner, PermissionManifest manifest, Identities identities) {
        if (!manifest.producer().id().equals(owner.producerId()) || manifest.producer().kind() != owner.kind()
                || !Set.copyOf(manifest.producer().expectedModules()).equals(Set.copyOf(owner.expectedModules()))
                || manifest.producer().ownedKeyPrefixes().stream().anyMatch(prefix -> owner.resourcePrefixes().stream().noneMatch(prefix::startsWith))) {
            throw new Rbac3RuleViolation("SERVICE_IDENTITY_DENIED");
        }
        Map<String, Identity> resources = caseIndex(identities.resources());
        Map<String, Identity> permissions = caseIndex(identities.permissions());
        Map<String, Identity> messages = caseIndex(identities.messages());
        for (PermissionManifest.ResourceDefinition resource : manifest.resources()) {
            owned(resource.key(), owner.resourcePrefixes());
            stable(resources.get(resource.key().toLowerCase(Locale.ROOT)), resource.key(), owner.producerId(), resource.type().name());
        }
        for (PermissionManifest.PermissionDefinition permission : manifest.permissionDefinitions()) {
            owned(permission.code(), owner.permissionPrefixes());
            stable(permissions.get(permission.code().toLowerCase(Locale.ROOT)), permission.code(), owner.producerId(), permission.meaning());
        }
        for (PermissionManifest.Message message : manifest.messages()) {
            String key = message.pageCode() + '/' + message.key();
            owned(key, owner.messagePrefixes());
            stable(messages.get(key.toLowerCase(Locale.ROOT)), key, owner.producerId(), "");
        }
        Set<String> localMessages = manifest.messages().stream().map(message -> message.pageCode() + '/' + message.key()).collect(Collectors.toSet());
        for (PermissionManifest.ResourceDefinition resource : manifest.resources()) validateI18n(resource.i18n(), localMessages, identities.messages());
        for (PermissionManifest.PermissionDefinition permission : manifest.permissionDefinitions()) validateI18n(permission.i18n(), localMessages, identities.messages());
        for (String code : manifest.permissionReferences()) {
            Identity referenced = identities.permissions().get(code);
            if (referenced == null || referenced.state().equals("RETIRED")) throw new Rbac3RuleViolation("RESOURCE_MANIFEST_INVALID");
        }
        for (PermissionManifest.ResourceReference reference : manifest.resourceReferences()) {
            Identity referenced = identities.resources().get(reference.key());
            if (referenced == null || referenced.state().equals("RETIRED")) throw new Rbac3RuleViolation("RESOURCE_MANIFEST_INVALID");
        }
    }

    private void validateI18n(PermissionManifest.I18nReference reference, Set<String> local, Map<String, Identity> existing) {
        for (String key : reference.keys()) {
            String id = reference.pageCode() + '/' + key;
            Identity previous = existing.get(id);
            if (!local.contains(id) && (previous == null || !previous.state().equals("ACTIVE"))) {
                throw new Rbac3RuleViolation("RESOURCE_MANIFEST_INVALID");
            }
        }
    }

    private Map<String, Identity> caseIndex(Map<String, Identity> values) {
        return values.values().stream().collect(Collectors.toMap(value -> value.key().toLowerCase(Locale.ROOT), Function.identity()));
    }

    private void owned(String key, List<String> prefixes) {
        if (prefixes.stream().noneMatch(key::startsWith)) throw new Rbac3RuleViolation("SERVICE_IDENTITY_DENIED");
    }

    private void stable(Identity old, String key, String owner, String semantics) {
        if (old != null && (!old.key().equals(key) || !old.owner().equals(owner) || !old.semantics().equals(semantics)
                || old.state().equals("RETIRED"))) throw new Rbac3RuleViolation("RESOURCE_MANIFEST_CONFLICT");
    }

    public AssignedIds assign(PermissionCatalogScopeRepository.Owner owner, PermissionManifest manifest, Identities identities,
                              String actor, Instant now) {
        Map<String, String> resources = new TreeMap<>();
        Map<String, String> permissions = new TreeMap<>();
        for (PermissionManifest.ResourceDefinition resource : manifest.resources()) {
            Identity existing = identities.resources().get(resource.key());
            String id = existing == null ? Long.toString(SnowflakeIdGenerator.nextLongId()) : existing.id();
            resources.put(resource.key(), id);
            if (existing == null) {
                Map<String, Object> params = identityParameters(owner, resource.key(), id, actor, now);
                params.put("type", resource.type().name());
                query("""
                        insert into rbac3_catalog_resource
                            (id,catalog_scope_id,registration_key,resource_type,owner_producer_id,created_at,created_by,updated_at,updated_by)
                        values (:id,:scope,:key,:type,:producer,:now,:actor,:now,:actor)
                        """, params).executeUpdate();
            }
        }
        for (PermissionManifest.PermissionDefinition permission : manifest.permissionDefinitions()) {
            Identity existing = identities.permissions().get(permission.code());
            String id = existing == null ? Long.toString(SnowflakeIdGenerator.nextLongId()) : existing.id();
            permissions.put(permission.code(), id);
            if (existing == null) {
                Map<String, Object> params = identityParameters(owner, permission.code(), id, actor, now);
                params.put("meaning", permission.meaning());
                query("""
                        insert into rbac3_catalog_permission
                            (id,catalog_scope_id,permission_code,meaning,owner_producer_id,created_at,created_by,updated_at,updated_by)
                        values (:id,:scope,:key,:meaning,:producer,:now,:actor,:now,:actor)
                        """, params).executeUpdate();
            }
        }
        for (PermissionManifest.Message message : manifest.messages()) {
            String key = message.pageCode() + '/' + message.key();
            if (!identities.messages().containsKey(key)) {
                Map<String, Object> params = new LinkedHashMap<>();
                params.put("scope", Long.parseLong(owner.scope().catalogScopeId()));
                params.put("producer", owner.producerId());
                params.put("page", message.pageCode());
                params.put("key", message.key());
                params.put("now", now);
                params.put("actor", actor);
                query("""
                        insert into rbac3_catalog_message_owner
                            (catalog_scope_id,page_code,message_key,owner_producer_id,created_at,created_by,updated_at,updated_by)
                        values (:scope,:page,:key,:producer,:now,:actor,:now,:actor)
                        """, params).executeUpdate();
            }
        }
        return new AssignedIds(resources, permissions);
    }

    public void saveVersions(CatalogScope scope, PermissionManifest manifest, long revision, AssignedIds ids, Identities identities) {
        Map<String, String> knownCodes = new TreeMap<>();
        identities.permissions().forEach((key, identity) -> knownCodes.put(key, identity.id()));
        knownCodes.putAll(ids.permissions());
        for (PermissionManifest.PermissionDefinition permission : manifest.permissionDefinitions()) {
            Map<String, Object> definition = Map.of("code", permission.code(), "meaning", permission.meaning(),
                    "i18n", canonicalizer.i18nMap(permission.i18n()), "lifecycle", permission.lifecycle().name());
            Map<String, Object> params = versionParameters(scope, manifest.producer().id(), revision);
            params.put("id", Long.parseLong(ids.permissions().get(permission.code())));
            params.put("code", permission.code());
            params.put("definition", CanonicalJson.write(definition));
            params.put("digest", CanonicalJson.digest(definition));
            params.put("i18n", CanonicalJson.write(canonicalizer.i18nMap(permission.i18n())));
            params.put("lifecycle", permission.lifecycle().name());
            query("""
                    insert into rbac3_catalog_permission_version
                        (catalog_scope_id,producer_id,producer_version,permission_id,permission_code,definition_json,definition_digest,i18n_json,lifecycle)
                    values (:scope,:producer,:revision,:id,:code,cast(:definition as jsonb),:digest,cast(:i18n as jsonb),:lifecycle)
                    """, params).executeUpdate();
        }
        for (PermissionManifest.ResourceDefinition resource : manifest.resources()) {
            long id = Long.parseLong(ids.resources().get(resource.key()));
            Map<String, Object> definition = canonicalizer.resourceMap(resource);
            Map<String, Object> params = versionParameters(scope, manifest.producer().id(), revision);
            params.put("id", id);
            params.put("key", resource.key());
            params.put("type", resource.type().name());
            params.put("lifecycle", resource.lifecycle().name());
            params.put("classification", resource.access().name());
            params.put("definition", CanonicalJson.write(definition));
            params.put("digest", CanonicalJson.digest(definition));
            params.put("target", CanonicalJson.write(resource.target()));
            params.put("i18n", CanonicalJson.write(canonicalizer.i18nMap(resource.i18n())));
            query("""
                    insert into rbac3_catalog_resource_version
                        (catalog_scope_id,producer_id,producer_version,resource_id,registration_key,resource_type,definition_lifecycle,
                         classification,definition_json,definition_digest,target_json,i18n_json)
                    values (:scope,:producer,:revision,:id,:key,:type,:lifecycle,:classification,
                            cast(:definition as jsonb),:digest,cast(:target as jsonb),cast(:i18n as jsonb))
                    """, params).executeUpdate();
            saveRequirement(scope, manifest.producer().id(), revision, id, "ACCESS", resource.requirement(), knownCodes);
            if (resource.fieldPolicy() != null) {
                saveRequirement(scope, manifest.producer().id(), revision, id, "PLAIN_READ", resource.fieldPolicy().plainRead(), knownCodes);
                saveRequirement(scope, manifest.producer().id(), revision, id, "MASKED_READ", resource.fieldPolicy().maskedRead(), knownCodes);
                saveRequirement(scope, manifest.producer().id(), revision, id, "WRITE", resource.fieldPolicy().write(), knownCodes);
            }
        }
    }

    private void saveRequirement(CatalogScope scope, String producer, long revision, long resourceId, String operation,
                                 PermissionRequirement requirement, Map<String, String> knownCodes) {
        if (requirement == null) return;
        List<PermissionRequirement> groups = requirement.groups();
        for (int groupIndex = 0; groupIndex < groups.size(); groupIndex++) {
            PermissionRequirement group = groups.get(groupIndex);
            if (group.access() == ResourceAccess.PUBLIC) continue;
            for (int codeIndex = 0; codeIndex < group.codes().size(); codeIndex++) {
                String code = group.codes().get(codeIndex);
                Map<String, Object> params = versionParameters(scope, producer, revision);
                params.put("resource", resourceId);
                params.put("operation", operation);
                params.put("groupIndex", groupIndex);
                params.put("mode", group.mode().name());
                params.put("code", code);
                params.put("permission", knownCodes.containsKey(code) ? Long.parseLong(knownCodes.get(code)) : null);
                params.put("codeIndex", codeIndex);
                query("""
                        insert into rbac3_catalog_resource_requirement
                            (catalog_scope_id,producer_id,producer_version,resource_id,operation,group_index,group_mode,permission_code,permission_id,code_index)
                        values (:scope,:producer,:revision,:resource,:operation,:groupIndex,:mode,:code,:permission,:codeIndex)
                        """, params).executeUpdate();
            }
        }
    }

    private Map<String, Object> identityParameters(PermissionCatalogScopeRepository.Owner owner, String key, String id, String actor, Instant now) {
        Map<String, Object> params = versionParameters(owner.scope(), owner.producerId(), 1);
        params.remove("revision");
        params.put("id", Long.parseLong(id));
        params.put("key", key);
        params.put("actor", actor);
        params.put("now", now);
        return params;
    }

    private Map<String, Object> versionParameters(CatalogScope scope, String producer, long revision) {
        Map<String, Object> params = new LinkedHashMap<>();
        params.put("scope", Long.parseLong(scope.catalogScopeId()));
        params.put("producer", producer);
        params.put("revision", revision);
        return params;
    }

    private Map<String, Identity> identities(List<?> rows) {
        Map<String, Identity> result = new TreeMap<>();
        for (Object value : rows) {
            Object[] row = (Object[]) value;
            Identity identity = new Identity(row[0].toString(), row[1].toString(), row[2].toString(), row[3].toString(), row[4].toString());
            result.put(identity.key(), identity);
        }
        return result;
    }

    private Query query(String sql, Map<String, Object> parameters) {
        Query query = entityManager.createNativeQuery(sql);
        parameters.forEach(query::setParameter);
        return query;
    }
}
