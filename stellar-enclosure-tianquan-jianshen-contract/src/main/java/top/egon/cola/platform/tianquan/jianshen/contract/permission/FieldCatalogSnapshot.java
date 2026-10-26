package top.egon.cola.platform.tianquan.jianshen.contract.permission;

import java.util.Collections;
import java.util.Map;
import java.util.Objects;
import java.util.TreeMap;

/** Read-only FIELD metadata from the current host build and the request's verified catalog version. */
public record FieldCatalogSnapshot(CatalogScope catalogScope, String catalogVersion, Map<String, FieldDefinition> fields) {
    public FieldCatalogSnapshot {
        Objects.requireNonNull(catalogScope, "catalogScope");
        catalogVersion = ManifestChecks.decimal(catalogVersion, "catalogVersion", false);
        if (fields == null || fields.isEmpty() || fields.size() > 256) throw new IllegalArgumentException("field batch must contain 1..256 keys");
        var values = new TreeMap<String, FieldDefinition>();
        fields.forEach((key, value) -> values.put(ManifestChecks.identifier(key, "field key", 256), Objects.requireNonNull(value, "field")));
        fields = Collections.unmodifiableMap(values);
    }

    public record FieldDefinition(ResourceAccess access, PermissionManifest.FieldPolicy fieldPolicy, boolean inputBinding) {
        public FieldDefinition { Objects.requireNonNull(access, "access"); }
    }
}
