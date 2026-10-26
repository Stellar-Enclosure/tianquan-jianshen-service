package top.egon.cola.platform.tianquan.jianshen.admin.authorization.runtime.catalog;

import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import top.egon.cola.platform.tianquan.jianshen.core.rule.Rbac3RuleViolation;
import java.time.Clock;
import java.util.UUID;

/** Bounded worker. Retried or late deliveries cannot publish through a different lease owner. */
@Component
@ConditionalOnProperty(prefix = "egon.cola.component.transactional-outbox.polling", name = "enabled", havingValue = "true")
public class PermissionSnapshotRebuildWorker {
    private final PermissionSnapshotRebuildRepository tasks;
    private final PermissionRuntimeSnapshotRepository snapshots;
    private final PermissionRuntimeProperties properties;
    private final Clock clock;
    private final String owner = "rbac-runtime-" + UUID.randomUUID();

    public PermissionSnapshotRebuildWorker(PermissionSnapshotRebuildRepository tasks, PermissionRuntimeSnapshotRepository snapshots,
                                           PermissionRuntimeProperties properties, Clock clock) {
        this.tasks = tasks; this.snapshots = snapshots; this.properties = properties; this.clock = clock;
    }

    @Scheduled(fixedDelayString = "${egon.tianquan-jianshen.catalog-runtime.rebuild-delay:1000}")
    public void poll() {
        var task = tasks.claim(owner);
        if (task == null) return;
        var activeTask = task;
        boolean succeeded = false;
        try {
            var bindings = properties.bindings().stream().filter(binding -> Long.toString(task.scopeId()).equals(binding.scope().catalogScopeId())).toList();
            if (bindings.isEmpty()) throw new IllegalStateException("AUTH_RUNTIME_BINDING_UNAVAILABLE");
            for (var binding : bindings) {
                long after = 0;
                while (true) {
                    if (!activeTask.leaseUntil().isAfter(clock.instant())) throw new IllegalStateException("AUTH_REBUILD_CLAIM_LOST");
                    var users = tasks.users(binding.scope().tenantId(), after);
                    if (users.isEmpty()) break;
                    for (long user : users) {
                        try { snapshots.rebuild(binding, user, activeTask); }
                        catch (Rbac3RuleViolation denied) {
                            if (!java.util.Set.of("IDENTITY_INACTIVE", "APPLICATION_BINDING_DENIED", "ROLE_ACTIVATION_ASSIGNMENT_REQUIRED",
                                    "ROLE_ACTIVATION_SET_INVALID").contains(denied.reasonCode())) throw denied;
                        }
                    }
                    after = users.getLast();
                    activeTask = tasks.renew(activeTask);
                }
            }
            succeeded = true;
        } finally { tasks.finish(activeTask, succeeded); }
    }
}
