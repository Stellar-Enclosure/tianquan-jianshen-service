package top.egon.cola.platform.tianquan.jianshen.starter.field;

import top.egon.cola.platform.tianquan.jianshen.contract.permission.PermissionManifest;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.ResourceAccess;
import java.util.Set;

/** Read and write are independent operations; a write grant never promotes a read decision. */
public final class PermissionFieldPolicy {
    public enum Read { OMIT, MASKED, PLAIN }
    private PermissionFieldPolicy() { }

    public static Read read(PermissionManifest.ResourceDefinition resource, Set<String> permissions) {
        if (resource.access() == ResourceAccess.PUBLIC) return Read.PLAIN;
        var rule = resource.fieldPolicy();
        if (rule == null) return Read.OMIT;
        if (rule.plainRead() != null && rule.plainRead().allows(permissions)) return Read.PLAIN;
        if (rule.maskedRead() != null && rule.maskedRead().allows(permissions)) return Read.MASKED;
        return Read.OMIT;
    }

    public static boolean writable(PermissionManifest.ResourceDefinition resource, Set<String> permissions,
                                   boolean actualInputBinding) {
        if (!actualInputBinding) return false;
        if (resource.access() == ResourceAccess.PUBLIC) return true;
        var rule = resource.fieldPolicy();
        return rule != null && rule.write() != null && rule.write().allows(permissions);
    }
}
