package top.egon.cola.platform.tianquan.jianshen.admin.registration.catalog.service;

import top.egon.cola.platform.tianquan.jianshen.admin.registration.catalog.domain.PermissionSourceEventIdentity;

import top.egon.cola.platform.tianquan.jianshen.admin.registration.catalog.domain.convertor.PermissionCatalogJson;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import top.egon.cola.component.outbox.api.OutboxMessage;
import top.egon.cola.component.outbox.api.OutboxReceipt;
import top.egon.cola.component.outbox.api.TransactionalOutbox;
import top.egon.cola.component.outbox.delivery.DeliveryContext;
import top.egon.cola.component.outbox.delivery.DeliveryResult;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.runtime.domain.vo.AuthorizationEventVO;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.runtime.repository.outbox.TransactionalOutboxAuthorizationEventPublisher;
import top.egon.cola.platform.tianquan.jianshen.admin.registration.catalog.controller.message.PermissionSourceDeliveryHandler;
import top.egon.cola.platform.tianquan.jianshen.admin.registration.catalog.repository.PermissionSourceOutboxRepository;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.ManifestRegistrationRequest;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.PermissionManifestCanonicalizer;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.SourceImportReceipt;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.SourceImportRequest;

import java.time.Clock;
import java.time.ZoneOffset;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

class PermissionSourceDeliveryHandlerTest {

    private final PermissionCatalogJson json = new PermissionCatalogJson(new ObjectMapper().registerModule(new JavaTimeModule()));
    private final PermissionSourceReceiptService receipts = mock(PermissionSourceReceiptService.class);
    private final PermissionSourceImportClient client = mock(PermissionSourceImportClient.class);
    private final PermissionSourceOutboxRepository outbox = mock(PermissionSourceOutboxRepository.class);
    private final PermissionSourceDeliveryHandler handler = new PermissionSourceDeliveryHandler(json, receipts, client);
    private SourceImportRequest source;
    private SourceImportReceipt receipt;
    private DeliveryContext event;

    @BeforeEach
    void prepare() {
        var manifest = PermissionCatalogFixture.manifest();
        var digests = new PermissionManifestCanonicalizer().digests(manifest);
        source = new SourceImportRequest(PermissionCatalogFixture.OPERATION, PermissionCatalogFixture.SCOPE, "api", "1", digests.manifestDigest(),
                manifest, digests, Map.of("app.read", "101"), Map.of("app.read", "201"));
        receipt = new SourceImportReceipt("300", source.operationId(), source.scope(), source.producerId(), source.producerVersion(),
                source.sourceVersion(), source.digests(), source.projectionDigest(), 1, 1, 1, PermissionCatalogFixture.NOW);
        var transactional = mock(TransactionalOutbox.class);
        when(transactional.enqueue(any())).thenAnswer(call -> {
            OutboxMessage message = call.getArgument(0);
            return new OutboxReceipt(message.messageId(), message.idempotencyKey(), true);
        });
        var publisher = new TransactionalOutboxAuthorizationEventPublisher(transactional, Clock.fixed(PermissionCatalogFixture.NOW, ZoneOffset.UTC));
        Map<String, String> payload = new LinkedHashMap<>();
        ManifestRegistrationRequest.targetMap(source.scope()).forEach((key, value) -> payload.put(key, value.toString()));
        payload.put("producerId", "api");
        payload.put("producerVersion", "1");
        payload.put("aggregateVersion", "1");
        payload.put("operationId", source.operationId());
        payload.put("manifestDigest", source.sourceVersion());
        publisher.enqueue(new AuthorizationEventVO(source.scope().tenantId(), "PERMISSION_PRODUCER", PermissionSourceEventIdentity.permissionSourceAggregateId("1", "api", 1),
                "PERMISSION_SOURCE_IMPORT_REQUESTED", payload, source.operationId()));
        ArgumentCaptor<OutboxMessage> captured = ArgumentCaptor.forClass(OutboxMessage.class);
        verify(transactional).enqueue(captured.capture());
        OutboxMessage message = captured.getValue();
        event = new DeliveryContext(message.messageId(), message.channel(), message.destination(), json.write(message.payload()),
                "application/json", "1", Map.of(), source.operationId(), 1, 5, PermissionCatalogFixture.NOW.plusSeconds(30));
        when(receipts.load(any(), anyString(), anyLong(), anyString(), anyString())).thenReturn(source);
        when(client.lookup(source)).thenReturn(Optional.empty());
        when(client.importSource(source)).thenReturn(receipt);
    }

    @Test
    void publisherAndConsumerUseTheSameScopeBoundMessageIdentity() {
        assertEquals(PermissionSourceEventIdentity.permissionSourceMessageId("10", "1", "api", 1, 1), event.messageId());
        assertEquals(DeliveryResult.Kind.SUCCESS, handler.deliver(event).kind());
        verify(client).lookup(source);
        verify(client).importSource(source);
        verify(receipts).accept(source, receipt);
    }

    @Test
    void unknownPostOutcomeRecoversReceiptWithoutAnotherPost() {
        when(client.lookup(source)).thenReturn(Optional.of(receipt));
        assertEquals(DeliveryResult.Kind.SUCCESS, handler.deliver(event).kind());
        verify(client, never()).importSource(any());
        verify(receipts).accept(source, receipt);
    }

    @Test
    void alreadyReadyDoesNotCallRemoteAuthorityAgain() {
        when(receipts.ready(source)).thenReturn(true);
        assertEquals(DeliveryResult.Kind.SUCCESS, handler.deliver(event).kind());
        verifyNoInteractions(client);
        verify(receipts, never()).accept(any(), any());
    }

    @Test
    void temporaryFailureDoesNotAdvanceOrPermanentlyFailCandidate() {
        when(client.lookup(source)).thenThrow(new PermissionSourceImportClient.MetadataTransferFailure("METADATA_AUTHORITY_UNAVAILABLE", true));
        assertEquals(DeliveryResult.Kind.RETRYABLE_FAILURE, handler.deliver(event).kind());
        verify(receipts, never()).accept(any(), any());
        verify(receipts, never()).fail(any(), anyLong(), anyString());
    }

    @Test
    void mismatchedReceiptPermanentlyFailsCandidateWithoutActivatingIt() {
        when(client.lookup(source)).thenThrow(new PermissionSourceImportClient.MetadataTransferFailure("METADATA_RECEIPT_MISMATCH", false));
        assertEquals(DeliveryResult.Kind.PERMANENT_FAILURE, handler.deliver(event).kind());
        verify(receipts).fail(source, 1, "METADATA_RECEIPT_MISMATCH");
        verify(receipts, never()).accept(any(), any());
    }

    @Test
    void eventFromAnotherTargetCannotUseTheOriginalMessageIdentity() {
        var changed = new DeliveryContext(event.messageId(), event.channel(), event.destination(), event.payload().replace("\"tenantId\":\"10\"", "\"tenantId\":\"11\""),
                event.contentType(), event.schemaVersion(), event.headers(), event.traceId(), event.attempt(), event.maxAttempts(), event.deadline());
        assertEquals(DeliveryResult.Kind.PERMANENT_FAILURE, handler.deliver(changed).kind());
        verifyNoInteractions(receipts, client);
    }
}
