package top.egon.cola.platform.tianquan.jianshen.contract.permission.annotation;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Repeatable;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.DefinitionLifecycle;

/** Declares an owned permission code with immutable business meaning. */
@Documented
@Target({ElementType.TYPE, ElementType.PACKAGE, ElementType.ANNOTATION_TYPE})
@Retention(RetentionPolicy.RUNTIME)
@Repeatable(PermissionDefinitions.class)
public @interface PermissionDefinition {

    String code();
    String meaning();
    String labelPage();
    String labelKey();
    DefinitionLifecycle lifecycle() default DefinitionLifecycle.ACTIVE;
}
