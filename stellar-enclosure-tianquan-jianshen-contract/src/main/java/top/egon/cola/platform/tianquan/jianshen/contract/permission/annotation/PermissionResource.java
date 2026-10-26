package top.egon.cola.platform.tianquan.jianshen.contract.permission.annotation;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.DefinitionLifecycle;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.PermissionManifest;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.ResourceAccess;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.ResourceType;

/** Stable resource identity; API targets are resolved from compiler-visible Spring mappings. */
@Documented
@Target({ElementType.TYPE, ElementType.METHOD, ElementType.FIELD, ElementType.RECORD_COMPONENT, ElementType.ANNOTATION_TYPE})
@Retention(RetentionPolicy.RUNTIME)
public @interface PermissionResource {

    String key();
    ResourceType type();
    String labelPage();
    String labelKey();
    ResourceAccess access() default ResourceAccess.PROTECTED;
    PermissionManifest.PrincipalType[] allowedPrincipals() default {PermissionManifest.PrincipalType.USER};
    String[] oauthScopes() default {};
    DefinitionLifecycle lifecycle() default DefinitionLifecycle.ACTIVE;
}
