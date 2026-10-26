package top.egon.cola.platform.tianquan.jianshen.contract.permission.annotation;

import java.lang.annotation.Documented;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/** One compile-time source translation. */
@Documented
@Target({})
@Retention(RetentionPolicy.RUNTIME)
public @interface LocalizedText {

    String locale();
    String text();
}
