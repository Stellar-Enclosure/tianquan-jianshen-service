package top.egon.cola.platform.tianquan.jianshen.starter.field;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Marks a JSON {@code @RequestBody} parameter or handler method for strict bounded JSON parsing,
 * automatic {@link SubmittedFieldSet} collection, and {@link PermissionFieldBindingGuard} enforcement.
 */
@Target({ElementType.PARAMETER, ElementType.METHOD})
@Retention(RetentionPolicy.RUNTIME)
@Documented
public @interface StrictFieldBinding {

    /**
     * Top-level JSON property names that must be explicitly present in the submitted JSON object.
     */
    String[] requiredFields() default {};

    /**
     * Maximum accepted JSON request body size in bytes.
     */
    int maxBytes() default 16 * 1024 * 1024 + 1024 * 1024;

    /**
     * Maximum accepted JSON nesting depth.
     */
    int maxNestingDepth() default 16;
}
