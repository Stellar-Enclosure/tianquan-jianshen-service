package top.egon.cola.platform.tianquan.jianshen.starter.field;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.*;
import com.fasterxml.jackson.databind.deser.BeanDeserializerBase;
import com.fasterxml.jackson.databind.deser.BeanDeserializerModifier;
import com.fasterxml.jackson.databind.deser.std.DelegatingDeserializer;
import com.fasterxml.jackson.databind.jsontype.TypeDeserializer;
import org.springframework.security.authorization.AuthorizationDeniedException;
import top.egon.cola.platform.tianquan.jianshen.starter.permission.PermissionPolicyRegistry;
import java.io.IOException;
import java.util.LinkedHashSet;
import java.util.Set;

/** Captures submitted JSON tokens against the actual Jackson input binder, before setters or constructors run. */
final class PermissionFieldDeserializerModifier extends BeanDeserializerModifier {
    private final PermissionPolicyRegistry registry;
    private final PermissionFieldBindingGuard guard;

    PermissionFieldDeserializerModifier(PermissionPolicyRegistry registry, PermissionFieldBindingGuard guard) {
        this.registry = registry; this.guard = guard;
    }

    @Override public JsonDeserializer<?> modifyDeserializer(DeserializationConfig config, BeanDescription bean,
                                                            JsonDeserializer<?> deserializer) {
        if (registry.fields(bean.getBeanClass()).isEmpty()) return deserializer;
        if (!(deserializer instanceof BeanDeserializerBase)) {
            throw new IllegalStateException("MANAGED_FIELD_CUSTOM_BINDER_REQUIRES_ADAPTER");
        }
        return new CapturingDeserializer(deserializer, bean.getBeanClass(), guard);
    }

    private static final class CapturingDeserializer extends DelegatingDeserializer {
        private final Class<?> dto;
        private final PermissionFieldBindingGuard guard;
        CapturingDeserializer(JsonDeserializer<?> delegate, Class<?> dto, PermissionFieldBindingGuard guard) {
            super(delegate); this.dto = dto; this.guard = guard;
        }
        @Override protected JsonDeserializer<?> newDelegatingInstance(JsonDeserializer<?> delegate) {
            return new CapturingDeserializer(delegate, dto, guard);
        }
        @Override public Object deserialize(JsonParser parser, DeserializationContext context) throws IOException {
            if (StrictSubmittedFieldBinder.isRequestVerified()) {
                return _delegatee.deserialize(parser, context);
            }
            try (JsonParser captured = capture(parser)) { return _delegatee.deserialize(captured, context); }
        }
        @Override public Object deserialize(JsonParser parser, DeserializationContext context, Object intoValue) throws IOException {
            if (StrictSubmittedFieldBinder.isRequestVerified()) {
                @SuppressWarnings("unchecked") JsonDeserializer<Object> delegate = (JsonDeserializer<Object>) _delegatee;
                return delegate.deserialize(parser, context, intoValue);
            }
            try (JsonParser captured = capture(parser)) {
                @SuppressWarnings("unchecked") JsonDeserializer<Object> delegate = (JsonDeserializer<Object>) _delegatee;
                return delegate.deserialize(captured, context, intoValue);
            }
        }
        @Override public Object deserializeWithType(JsonParser parser, DeserializationContext context, TypeDeserializer type) throws IOException {
            if (StrictSubmittedFieldBinder.isRequestVerified()) {
                return _delegatee.deserializeWithType(parser, context, type);
            }
            try (JsonParser captured = capture(parser)) { return _delegatee.deserializeWithType(captured, context, type); }
        }
        private JsonParser capture(JsonParser parser) throws IOException {
            parser.enable(JsonParser.Feature.STRICT_DUPLICATE_DETECTION);
            JsonNode body = parser.readValueAsTree();
            if (!body.isObject()) throw guard.denyInput("FIELD_INPUT_OBJECT_REQUIRED");
            if (!(_delegatee instanceof BeanDeserializerBase bean)) {
                throw guard.denyInput("MANAGED_FIELD_BINDER_UNAVAILABLE");
            }
            Set<String> submitted = new LinkedHashSet<>();
            Set<String> writable = new LinkedHashSet<>();
            var names = body.fieldNames();
            while (names.hasNext()) {
                String raw = names.next();
                var property = bean.findProperty(raw);
                if (property == null || !submitted.add(property.getName())) {
                    throw guard.denyInput("FIELD_BINDING_UNKNOWN_OR_DUPLICATE");
                }
                writable.add(property.getName());
            }
            guard.require(dto, new SubmittedFieldSet(submitted), writable);
            JsonParser captured = body.traverse(parser.getCodec());
            captured.nextToken();
            return captured;
        }
    }
}
