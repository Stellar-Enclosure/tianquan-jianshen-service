package top.egon.cola.platform.tianquan.jianshen.contract.permission.annotation;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/** Compiler-only inventory of a native HTTP dispatcher whose activated route table owns paths and methods. */
@Documented
@Target(ElementType.METHOD)
@Retention(RetentionPolicy.SOURCE)
public @interface PermissionNativeDispatcher {
    Class<?> routeType();
    String pathAccessor();
    String methodsAccessor();
}
