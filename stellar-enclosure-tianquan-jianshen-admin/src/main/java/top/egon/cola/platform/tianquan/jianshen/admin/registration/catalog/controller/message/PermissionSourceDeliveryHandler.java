package top.egon.cola.platform.tianquan.jianshen.admin.registration.catalog.controller.message;

import top.egon.cola.platform.tianquan.jianshen.admin.registration.catalog.domain.PermissionSourceEventIdentity;

import org.springframework.stereotype.Component;
import top.egon.cola.component.outbox.deadletter.OutboxDeadLetterListener;
import top.egon.cola.component.outbox.delivery.DeliveryContext;
import top.egon.cola.component.outbox.delivery.DeliveryHandler;
import top.egon.cola.component.outbox.delivery.DeliveryResult;
import top.egon.cola.component.outbox.event.OutboxDeadLetterEvent;
import top.egon.cola.platform.tianquan.jianshen.admin.registration.catalog.domain.convertor.PermissionCatalogJson;
import top.egon.cola.platform.tianquan.jianshen.admin.registration.catalog.service.PermissionSourceImportClient;
import top.egon.cola.platform.tianquan.jianshen.admin.registration.catalog.service.PermissionSourceReceiptService;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.CatalogScope;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.ManifestRegistrationRequest;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.SourceImportRequest;
import top.egon.cola.platform.tianquan.jianshen.core.rule.Rbac3RuleViolation;

import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;

/** Outbox retries recover the original remote receipt before attempting the same idempotent import. */
@Component
public class PermissionSourceDeliveryHandler implements DeliveryHandler, OutboxDeadLetterListener {

    private final PermissionCatalogJson json;
    private final PermissionSourceReceiptService receipts;
    private final PermissionSourceImportClient client;

    public PermissionSourceDeliveryHandler(PermissionCatalogJson json, PermissionSourceReceiptService receipts,
                                           PermissionSourceImportClient client) {
        this.json = json;
        this.receipts = receipts;
        this.client = client;
    }

    @Override
    public String channel() {
        return PermissionSourceEventIdentity.PERMISSION_SOURCE_CHANNEL;
    }

    @Override
    public void validateDestination(String destination) {
        if (!PermissionSourceEventIdentity.PERMISSION_SOURCE_DESTINATION.equals(destination)) {
            throw new IllegalArgumentException("invalid permission source destination");
        }
    }

    @Override
    public DeliveryResult deliver(DeliveryContext context) {
        SourceImportRequest source = null;
        long metadataRevision = 0;
        try {
            validateDestination(context.destination());
            if (!channel().equals(context.channel()) || !"1".equals(context.schemaVersion())) {
                throw new IllegalArgumentException("invalid permission source envelope");
            }
            var delivery = load(context.messageId(), context.payload());
            source = delivery.source();
            metadataRevision = delivery.metadataRevision();
            if (receipts.ready(source)) return DeliveryResult.success();
            var existing = client.lookup(source);
            var receipt = existing.isPresent() ? existing.get() : client.importSource(source);
            receipts.accept(source, receipt);
            return DeliveryResult.success();
        } catch (PermissionSourceImportClient.MetadataTransferFailure failure) {
            if (failure.retryable()) return DeliveryResult.retryableFailure(failure.getMessage(), "Metadata authority is unavailable");
            if (source != null) receipts.fail(source, metadataRevision, failure.getMessage());
            return DeliveryResult.permanentFailure(failure.getMessage(), "Metadata authority rejected the source import");
        } catch (Rbac3RuleViolation failure) {
            if ("AUTH_RUNTIME_UNAVAILABLE".equals(failure.reasonCode()) || "AUTH_SNAPSHOT_NOT_READY".equals(failure.reasonCode())) {
                return DeliveryResult.retryableFailure("METADATA_LOCAL_AUTHORITY_UNAVAILABLE", "Local catalog authority is unavailable");
            }
            if (source != null) receipts.fail(source, metadataRevision, "METADATA_LOCAL_RECEIPT_REJECTED");
            return DeliveryResult.permanentFailure("METADATA_LOCAL_RECEIPT_REJECTED", "Local catalog rejected the source receipt");
        } catch (IllegalArgumentException invalid) {
            return DeliveryResult.permanentFailure("METADATA_EVENT_INVALID", "Invalid permission source event");
        } catch (RuntimeException unavailable) {
            return DeliveryResult.retryableFailure("METADATA_LOCAL_AUTHORITY_UNAVAILABLE", "Local catalog authority is unavailable");
        }
    }

    @Override
    public void onDead(OutboxDeadLetterEvent event) {
        if (!channel().equals(event.channel()) || !PermissionSourceEventIdentity.PERMISSION_SOURCE_DESTINATION.equals(event.destination())) return;
        receipts.deadPayload(event.messageId()).ifPresent(payload -> {
            var delivery = load(event.messageId(), payload);
            receipts.fail(delivery.source(), delivery.metadataRevision(), "METADATA_DELIVERY_EXHAUSTED");
        });
    }

    private record SourceDelivery(SourceImportRequest source, long metadataRevision) { }

    private SourceDelivery load(String messageId, String payload) {
        if (payload == null || payload.getBytes(StandardCharsets.UTF_8).length > 64 * 1024) {
            throw new IllegalArgumentException("permission source event exceeds its byte limit");
        }
        Map<String, Object> envelope = json.readObject(payload);
        PermissionCatalogJson.fields(envelope, "eventId", "eventType", "schemaVersion", "occurredAt", "tenantId",
                "aggregateType", "aggregateId", "aggregateVersion", "traceId", "payload");
        if (!Integer.valueOf(1).equals(envelope.get("schemaVersion")) || !messageId.equals(envelope.get("eventId"))
                || !"PERMISSION_PRODUCER".equals(envelope.get("aggregateType"))
                || !PermissionSourceEventIdentity.PERMISSION_SOURCE_DESTINATION.equals(envelope.get("eventType"))) {
            throw new IllegalArgumentException("permission source event identity mismatch");
        }
        Map<String, Object> body = PermissionCatalogJson.object(envelope, "payload");
        PermissionCatalogJson.fields(body, "catalogScopeId", "tenantId", "businessCode", "applicationCode", "namespaceCode", "environment",
                "producerId", "producerVersion", "aggregateVersion", "operationId", "manifestDigest");
        Map<String, Object> targetValues = new LinkedHashMap<>();
        for (String key : new String[]{"catalogScopeId", "tenantId", "businessCode", "applicationCode", "namespaceCode", "environment"}) {
            targetValues.put(key, PermissionCatalogJson.text(body, key));
        }
        CatalogScope target = json.scope(targetValues);
        String producer = new ManifestRegistrationRequest.Target(target, PermissionCatalogJson.text(body, "producerId")).producerId();
        String revision = PermissionCatalogJson.text(body, "producerVersion");
        long version = Long.parseLong(revision);
        String generation = PermissionCatalogJson.text(body, "aggregateVersion");
        long metadataRevision = Long.parseLong(generation);
        if (metadataRevision <= 0 || !Long.toString(metadataRevision).equals(generation) || version <= 0 || !Long.toString(version).equals(revision)
                || envelope.get("aggregateVersion") == null || !generation.equals(envelope.get("aggregateVersion").toString())
                || !target.tenantId().equals(envelope.get("tenantId"))
                || !PermissionSourceEventIdentity.permissionSourceAggregateId(target.catalogScopeId(), producer, version).equals(envelope.get("aggregateId"))
                || !messageId.equals(PermissionSourceEventIdentity.permissionSourceMessageId(
                target.tenantId(), target.catalogScopeId(), producer, version, metadataRevision))) {
            throw new IllegalArgumentException("permission source event target mismatch");
        }
        return new SourceDelivery(receipts.load(target, producer, version, PermissionCatalogJson.text(body, "operationId"),
                PermissionCatalogJson.text(body, "manifestDigest")), metadataRevision);
    }
}
