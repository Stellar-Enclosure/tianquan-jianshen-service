package top.egon.cola.platform.tianquan.jianshen.starter.permission;

import top.egon.cola.platform.tianquan.jianshen.contract.authorization.RuntimePolicyBinding;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.CatalogScope;
import java.util.List;
import java.util.Map;

/** Local Runtime evidence carried only as an exception cause; it contains no credential or user data. */
public final class RuntimeBindingMismatchEvidence extends RuntimeException {
    private final CatalogScope scope;
    private final String catalogVersion;
    private final String policyVersion;
    private final RuntimePolicyBinding selected;
    private final Map<String, Object> configuredProducer;
    private final List<String> failedChecks;

    public RuntimeBindingMismatchEvidence(CatalogScope scope, String catalogVersion, String policyVersion,
            RuntimePolicyBinding selected, Map<String, Object> configuredProducer, List<String> failedChecks) {
        super("Runtime binding mismatch", null, false, false);
        this.scope = java.util.Objects.requireNonNull(scope, "scope");
        this.catalogVersion = java.util.Objects.requireNonNull(catalogVersion, "catalogVersion");
        this.policyVersion = java.util.Objects.requireNonNull(policyVersion, "policyVersion");
        this.selected = java.util.Objects.requireNonNull(selected, "selected");
        this.configuredProducer = Map.copyOf(configuredProducer);
        this.failedChecks = List.copyOf(failedChecks);
    }
    public CatalogScope scope() { return scope; }
    public String catalogVersion() { return catalogVersion; }
    public String policyVersion() { return policyVersion; }
    public RuntimePolicyBinding selected() { return selected; }
    public Map<String, Object> configuredProducer() { return configuredProducer; }
    public List<String> failedChecks() { return failedChecks; }
}
