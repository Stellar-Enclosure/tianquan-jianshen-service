package top.egon.cola.platform.tianquan.jianshen.contract.permission.annotation;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.PermissionManifest;

/** Independent field operations. An omitted group denies that operation. */
@Documented
@Target({ElementType.FIELD, ElementType.METHOD, ElementType.RECORD_COMPONENT, ElementType.ANNOTATION_TYPE})
@Retention(RetentionPolicy.RUNTIME)
public @interface FieldPermissions {

    PermissionManifest.JsonFieldType valueType();
    PermissionGroup plainRead() default @PermissionGroup;
    PermissionGroup maskedRead() default @PermissionGroup;
    PermissionGroup write() default @PermissionGroup;
    String masker() default "";
}
