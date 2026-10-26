package top.egon.cola.platform.tianquan.jianshen.admin.config.permission;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.CatalogScope;

import java.net.URI;
import java.util.Map;

/** Fixed destination bindings; OAuth credentials remain in Spring's client registration configuration. */
@Component
@ConfigurationProperties(prefix = "egon.tianquan-jianshen.permission-catalog.metadata", ignoreUnknownFields = false)
public class PermissionMetadataProperties {

    public record Binding(CatalogScope target, URI baseUri, String registrationId, String appId, URI resourceUri) {
        public Binding {
            if (target == null || baseUri == null || !"https".equalsIgnoreCase(baseUri.getScheme()) || baseUri.getHost() == null
                    || baseUri.getUserInfo() != null || baseUri.getQuery() != null || baseUri.getFragment() != null
                    || !baseUri.normalize().equals(baseUri) || registrationId == null || registrationId.isBlank()
                    || appId == null || appId.isBlank() || resourceUri == null || !resourceUri.isAbsolute()
                    || resourceUri.getUserInfo() != null || resourceUri.getFragment() != null) {
                throw new IllegalArgumentException("invalid permission metadata destination binding");
            }
            baseUri = URI.create(baseUri.toASCIIString().replaceAll("/+$", "") + "/");
        }
    }

    private Map<String, Binding> bindings = Map.of();

    public Map<String, Binding> getBindings() {
        return bindings;
    }

    public void setBindings(Map<String, Binding> bindings) {
        if (bindings == null || bindings.size() > 256) throw new IllegalArgumentException("invalid metadata destination bindings");
        bindings.forEach((id, binding) -> {
            if (binding == null || !id.equals(binding.target().catalogScopeId())) throw new IllegalArgumentException("metadata scope binding mismatch");
        });
        this.bindings = Map.copyOf(bindings);
    }
}
