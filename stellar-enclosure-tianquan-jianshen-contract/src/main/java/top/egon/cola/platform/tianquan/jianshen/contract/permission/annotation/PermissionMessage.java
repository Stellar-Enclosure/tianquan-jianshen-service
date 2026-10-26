package top.egon.cola.platform.tianquan.jianshen.contract.permission.annotation;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Repeatable;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/** Source defaults travel with the producer; these are not human translation overrides. */
@Documented
@Target({ElementType.TYPE, ElementType.PACKAGE, ElementType.ANNOTATION_TYPE})
@Retention(RetentionPolicy.RUNTIME)
@Repeatable(PermissionMessages.class)
public @interface PermissionMessage {

    String pageCode();
    String key();
    String defaultLocale();
    LocalizedText[] defaults();
}
