package top.egon.cola.platform.tianquan.jianshen.starter.field;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import top.egon.cola.platform.tianquan.jianshen.starter.permission.PermissionExecutionGuard;

/** Export/RPC adapters consume this authorized tree rather than serializing the original entity directly. */
public final class PermissionOutputProjection {
    private final PermissionExecutionGuard api;
    private final ObjectMapper mapper;

    public PermissionOutputProjection(PermissionExecutionGuard api, ObjectMapper mapper) {
        this.api = api;
        this.mapper = mapper;
    }

    public JsonNode project(String resourceKey, Object value) {
        try (var boundary = api.open(resourceKey)) {
            return mapper.valueToTree(value);
        }
    }
}
