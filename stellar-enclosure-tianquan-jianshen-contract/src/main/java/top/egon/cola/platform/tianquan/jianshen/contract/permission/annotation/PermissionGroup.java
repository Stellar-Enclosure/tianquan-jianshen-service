package top.egon.cola.platform.tianquan.jianshen.contract.permission.annotation;

import java.lang.annotation.Documented;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.PermissionMode;

/** A nested field rule; an empty default represents an absent, denied operation. */
@Documented
@Target({})
@Retention(RetentionPolicy.RUNTIME)
public @interface PermissionGroup {

    PermissionMode mode() default PermissionMode.ALL;
    String[] codes() default {};
}
