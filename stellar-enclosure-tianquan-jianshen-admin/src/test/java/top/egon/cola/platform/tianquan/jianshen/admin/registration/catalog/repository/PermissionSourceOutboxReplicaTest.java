package top.egon.cola.platform.tianquan.jianshen.admin.registration.catalog.repository;

import java.util.List;
import java.util.function.Supplier;
import org.junit.jupiter.api.Test;
import top.egon.cola.component.outbox.persistence.OutboxShardContext;
import top.egon.cola.component.outbox.persistence.OutboxTechnicalContextExecutor;
import top.egon.cola.component.outbox.persistence.po.OutboxMessagePO;
import top.egon.cola.component.outbox.persistence.repository.OutboxMessageRepository;
import top.egon.cola.component.outbox.store.OutboxStatus;
import top.egon.cola.platform.tianquan.jianshen.admin.registration.catalog.domain.PermissionSourceEventIdentity;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.CatalogScope;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

class PermissionSourceOutboxReplicaTest {
    @Test
    void statusLookupUsesReplicaStatementInTheSingleOwnedSlot() {
        var messages = mock(OutboxMessageRepository.class);
        var context = mock(OutboxTechnicalContextExecutor.class);
        when(context.execute(any())).thenAnswer(call -> ((Supplier<?>) call.getArgument(0)).get());
        var scope = new CatalogScope("1", "10", "biz", "app", "default", "test");
        String id = PermissionSourceEventIdentity.permissionSourceMessageId("10", "1", "api", 2L, 3L);
        when(messages.selectReplicaByMessageId(id)).thenAnswer(call -> {
            assertThat(OutboxShardContext.isActive()).isTrue();
            assertThat(OutboxShardContext.currentSlot()).isZero();
            return List.of(OutboxMessagePO.builder().messageId(id)
                    .channel(PermissionSourceEventIdentity.PERMISSION_SOURCE_CHANNEL)
                    .destination(PermissionSourceEventIdentity.PERMISSION_SOURCE_DESTINATION)
                    .status(OutboxStatus.DEAD).build());
        });
        var repository = new PermissionSourceOutboxRepository(messages, context);

        assertThat(repository.deadForRead(scope, "api", 2L, 3L)).isTrue();
        doReturn(List.of(OutboxMessagePO.builder().messageId(id)
                .channel("other-channel").destination(PermissionSourceEventIdentity.PERMISSION_SOURCE_DESTINATION)
                .status(OutboxStatus.DEAD).build())).when(messages).selectReplicaByMessageId(id);
        assertThat(repository.deadForRead(scope, "api", 2L, 3L)).isFalse();
        assertThat(OutboxShardContext.isActive()).isFalse();
        verify(messages, never()).selectExistingByIdentity(anyString(), any());
    }

    @Test
    void rejectsAnotherShardInsteadOfReadingTheWrongOutboxGroup() {
        var messages = mock(OutboxMessageRepository.class);
        var context = mock(OutboxTechnicalContextExecutor.class);
        var repository = new PermissionSourceOutboxRepository(messages, context);
        var scope = new CatalogScope("1", "10", "biz", "app", "default", "test");
        OutboxShardContext.withSlot(7, () -> {
            assertThatThrownBy(() -> repository.deadForRead(scope, "api", 2L, 3L))
                    .isInstanceOf(IllegalStateException.class).hasMessage("RBAC_OUTBOX_SHARD_UNSUPPORTED");
            return null;
        });
        verifyNoInteractions(messages, context);
    }
}
