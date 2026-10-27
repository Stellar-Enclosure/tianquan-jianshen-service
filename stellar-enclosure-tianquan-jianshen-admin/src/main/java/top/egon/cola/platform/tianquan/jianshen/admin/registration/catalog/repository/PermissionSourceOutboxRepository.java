package top.egon.cola.platform.tianquan.jianshen.admin.registration.catalog.repository;

import top.egon.cola.platform.tianquan.jianshen.admin.registration.catalog.domain.PermissionSourceEventIdentity;

import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Repository;
import top.egon.cola.component.outbox.persistence.OutboxTechnicalContextExecutor;
import top.egon.cola.component.outbox.persistence.OutboxShardContext;
import top.egon.cola.component.outbox.persistence.po.OutboxMessagePO;
import top.egon.cola.component.outbox.persistence.repository.OutboxMessageRepository;
import top.egon.cola.component.outbox.store.OutboxStatus;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.CatalogScope;

import java.util.Optional;

/** Reads existing Outbox facts through its technical-owner context instead of assuming physical table routing. */
@Repository
public class PermissionSourceOutboxRepository {

    private final OutboxMessageRepository messages;
    private final OutboxTechnicalContextExecutor technicalContext;

    public PermissionSourceOutboxRepository(@Qualifier("outboxMessageRepository") OutboxMessageRepository messages,
                                            @Qualifier("outboxTechnicalContextExecutor") OutboxTechnicalContextExecutor technicalContext) {
        this.messages = messages;
        this.technicalContext = technicalContext;
    }

    public Optional<OutboxMessagePO> find(String messageId) {
        return technicalContext.execute(() -> messages.selectExistingByIdentity(messageId, null)).stream()
                .filter(message -> messageId.equals(message.getMessageId())
                        && PermissionSourceEventIdentity.PERMISSION_SOURCE_CHANNEL.equals(message.getChannel())
                        && PermissionSourceEventIdentity.PERMISSION_SOURCE_DESTINATION.equals(message.getDestination()))
                .findFirst();
    }

    public boolean dead(CatalogScope scope, String producer, long revision, long metadataRevision) {
        String id = PermissionSourceEventIdentity.permissionSourceMessageId(scope.tenantId(), scope.catalogScopeId(), producer, revision, metadataRevision);
        return find(id).map(message -> message.getStatus() == OutboxStatus.DEAD).orElse(false);
    }

    /** RBAC currently admits one primary group, so its outbox slot is always zero. */
    public boolean deadForRead(CatalogScope scope, String producer, long revision, long metadataRevision) {
        if (OutboxShardContext.isActive() && OutboxShardContext.currentSlot() != 0) {
            throw new IllegalStateException("RBAC_OUTBOX_SHARD_UNSUPPORTED");
        }
        String id = PermissionSourceEventIdentity.permissionSourceMessageId(scope.tenantId(), scope.catalogScopeId(), producer, revision, metadataRevision);
        return OutboxShardContext.withSlot(0, () -> technicalContext.execute(() -> messages.selectReplicaByMessageId(id)))
                .stream().anyMatch(message -> id.equals(message.getMessageId())
                        && PermissionSourceEventIdentity.PERMISSION_SOURCE_CHANNEL.equals(message.getChannel())
                        && PermissionSourceEventIdentity.PERMISSION_SOURCE_DESTINATION.equals(message.getDestination())
                        && message.getStatus() == OutboxStatus.DEAD);
    }
}
