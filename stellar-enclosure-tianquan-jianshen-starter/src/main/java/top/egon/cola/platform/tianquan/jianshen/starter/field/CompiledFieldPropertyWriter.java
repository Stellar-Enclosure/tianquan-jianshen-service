package top.egon.cola.platform.tianquan.jianshen.starter.field;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.fasterxml.jackson.databind.ser.BeanPropertyWriter;
import top.egon.cola.component.common.desensitize.annotation.SensitiveType;
import top.egon.cola.component.common.desensitize.strategy.SensitiveStrategyRegistry;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.PermissionManifest;
import top.egon.cola.platform.tianquan.jianshen.starter.permission.PermissionPolicyRegistry;
import top.egon.cola.platform.tianquan.jianshen.starter.security.CurrentRbac3User;

/** Projection-only writer; authorization never mutates the source object. */
final class CompiledFieldPropertyWriter extends BeanPropertyWriter {
    private final PermissionManifest.ResourceDefinition resource;
    private final PermissionPolicyRegistry registry;
    private final CurrentRbac3User users;
    private final SensitiveStrategyRegistry maskers;
    private final PermissionFieldBindingGuard fieldGuard;

    CompiledFieldPropertyWriter(BeanPropertyWriter source, PermissionManifest.ResourceDefinition resource,
            PermissionPolicyRegistry registry, CurrentRbac3User users, SensitiveStrategyRegistry maskers, PermissionFieldBindingGuard fieldGuard) {
        super(source);
        this.resource = resource;
        this.registry = registry;
        this.users = users;
        this.maskers = maskers; this.fieldGuard = fieldGuard;
    }

    @Override public void serializeAsField(Object bean, JsonGenerator generator, SerializerProvider provider) throws Exception {
        var jsonProperty = getAnnotation(com.fasterxml.jackson.annotation.JsonProperty.class);
        if (fieldGuard != null && fieldGuard.anonymousRead(resource,
                jsonProperty != null && jsonProperty.access() == com.fasterxml.jackson.annotation.JsonProperty.Access.READ_ONLY)) {
            super.serializeAsField(bean, generator, provider); return;
        }
        var user = users.current().orElse(null);
        PermissionFieldPolicy.Read decision;
        if (user == null) {
            var authentication = org.springframework.security.core.context.SecurityContextHolder.getContext().getAuthentication();
            if (fieldGuard == null || authentication == null || !authentication.isAuthenticated()
                    || !(authentication.getPrincipal() instanceof top.egon.cola.platform.tianquan.shoubing.contract.ServiceIdentityPrincipal service)) return;
            decision = fieldGuard.serviceRead(resource, service);
        } else {
            registry.requireActive(user.snapshot(), resource.key());
            decision = fieldGuard == null ? PermissionFieldPolicy.read(resource, user.permissions()) : fieldGuard.userRead(resource, user);
        }
        if (decision == PermissionFieldPolicy.Read.OMIT) return;
        if (decision == PermissionFieldPolicy.Read.PLAIN) {
            super.serializeAsField(bean, generator, provider);
            return;
        }
        Object value = get(bean);
        if (value == null) {
            generator.writeFieldName(getSerializedName()); generator.writeNull(); return;
        }
        if (!(value instanceof String text)) return;
        String masked;
        try {
            SensitiveType type = switch (resource.fieldPolicy().masker()) {
                case "FIXED" -> SensitiveType.FULL;
                case "EMAIL" -> SensitiveType.EMAIL;
                case "PHONE" -> SensitiveType.MOBILE;
                case "BANK_ACCOUNT" -> SensitiveType.BANK_CARD;
                default -> null;
            };
            if (type == null) return;
            masked = maskers.mask(type, text);
        } catch (RuntimeException failedMasking) { return; }
        if (masked == null) return;
        generator.writeFieldName(getSerializedName()); generator.writeString(masked);
    }
}
