package top.egon.cola.platform.tianquan.jianshen.starter.field;

import com.fasterxml.jackson.databind.BeanDescription;
import com.fasterxml.jackson.databind.SerializationConfig;
import com.fasterxml.jackson.databind.ser.BeanPropertyWriter;
import com.fasterxml.jackson.databind.ser.BeanSerializerModifier;
import top.egon.cola.component.common.desensitize.annotation.Sensitive;
import top.egon.cola.component.common.desensitize.annotation.SensitiveScene;
import top.egon.cola.component.common.desensitize.metadata.SensitiveMetadataResolver;
import top.egon.cola.component.common.desensitize.strategy.SensitiveStrategyRegistry;
import top.egon.cola.platform.tianquan.jianshen.starter.security.CurrentRbac3User;

import java.util.ArrayList;
import java.util.List;

final class Rbac3FieldSerializerModifier extends BeanSerializerModifier {

    private final CurrentRbac3User currentUser;
    private final SensitiveStrategyRegistry strategyRegistry;
    private final top.egon.cola.platform.tianquan.jianshen.starter.permission.PermissionPolicyRegistry policies;
    private final PermissionFieldBindingGuard fieldGuard;
    private final SensitiveMetadataResolver metadataResolver =
            new SensitiveMetadataResolver();

    Rbac3FieldSerializerModifier(
            CurrentRbac3User currentUser,
            SensitiveStrategyRegistry strategyRegistry) {
        this(currentUser, strategyRegistry, null, null);
    }

    Rbac3FieldSerializerModifier(CurrentRbac3User currentUser, SensitiveStrategyRegistry strategyRegistry,
            top.egon.cola.platform.tianquan.jianshen.starter.permission.PermissionPolicyRegistry policies, PermissionFieldBindingGuard fieldGuard) {
        this.currentUser = currentUser;
        this.strategyRegistry = strategyRegistry;
        this.policies = policies; this.fieldGuard = fieldGuard;
    }

    @Override
    public List<BeanPropertyWriter> changeProperties(
            SerializationConfig config,
            BeanDescription beanDesc,
            List<BeanPropertyWriter> beanProperties) {
        List<BeanPropertyWriter> result = new ArrayList<>(beanProperties.size());
        var compiled = policies == null ? java.util.Map.<String, top.egon.cola.platform.tianquan.jianshen.contract.permission.PermissionManifest.ResourceDefinition>of()
                : policies.fields(beanDesc.getBeanClass());
        for (BeanPropertyWriter property : beanProperties) {
            if (!compiled.isEmpty()) {
                var field = compiled.get(property.getName());
                if (field == null) throw new IllegalStateException("COMPILED_OUTPUT_FIELD_UNDECLARED");
                result.add(new CompiledFieldPropertyWriter(property, field, policies, currentUser, strategyRegistry, fieldGuard));
                continue;
            }
            RBACFieldResource resource = property.getAnnotation(RBACFieldResource.class);
            Sensitive staticSensitive = metadataResolver.resolve(
                    property.getAnnotation(Sensitive.class), SensitiveScene.RESPONSE)
                    .orElse(null);
            result.add(resource == null
                    ? property
                    : new Rbac3FieldPropertyWriter(
                    property, resource, staticSensitive, currentUser, strategyRegistry));
        }
        return result;
    }
}
