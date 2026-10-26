package top.egon.cola.platform.tianquan.jianshen.contract.permission.annotation;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Repeatable;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.PermissionMode;

/** One nonempty group. Every group on the type and method is combined with AND. */
@Documented
@Target({ElementType.TYPE, ElementType.METHOD, ElementType.ANNOTATION_TYPE})
@Retention(RetentionPolicy.RUNTIME)
@Repeatable(PermissionGroups.class)
public @interface RequiresPermissions {

    PermissionMode mode() default PermissionMode.ALL;
    String[] codes();
}
