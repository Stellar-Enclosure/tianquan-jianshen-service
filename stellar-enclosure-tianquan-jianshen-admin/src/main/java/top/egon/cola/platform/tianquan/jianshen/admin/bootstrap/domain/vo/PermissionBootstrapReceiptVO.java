package top.egon.cola.platform.tianquan.jianshen.admin.bootstrap.domain.vo;

import top.egon.cola.platform.tianquan.jianshen.contract.permission.CatalogScope;

import java.time.Instant;
import java.util.List;
import java.util.Map;

/** Immutable, secret-free original result recovered from the owning database audit transaction. */
public record PermissionBootstrapReceiptVO(int schemaVersion, String stage, String operationId, String commandDigest,
        CatalogScope target, String applicationId, String ddcBusinessId, String ddcApplicationId,
        List<String> producerIds, Map<String, String> facts, Instant completedAt) {
    public PermissionBootstrapReceiptVO {
        producerIds = List.copyOf(producerIds);
        facts = Map.copyOf(facts);
    }
}
