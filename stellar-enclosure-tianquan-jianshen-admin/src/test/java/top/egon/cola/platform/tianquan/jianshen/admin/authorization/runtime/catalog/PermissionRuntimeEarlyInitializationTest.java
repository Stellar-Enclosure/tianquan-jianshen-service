package top.egon.cola.platform.tianquan.jianshen.admin.authorization.runtime.catalog;

import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;
import org.springframework.aop.support.AopUtils;
import org.springframework.beans.factory.config.BeanPostProcessor;
import org.springframework.context.annotation.AnnotationConfigApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.context.annotation.Lazy;
import org.springframework.core.PriorityOrdered;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.annotation.EnableTransactionManagement;
import org.springframework.transaction.support.AbstractPlatformTransactionManager;
import org.springframework.transaction.support.DefaultTransactionStatus;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import top.egon.cola.platform.tianquan.jianshen.contract.authorization.SystemAuthorizationSnapshot;
import top.egon.cola.platform.tianquan.jianshen.starter.client.Rbac3AuthorizationClient;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;
import static top.egon.cola.platform.tianquan.jianshen.admin.authorization.runtime.catalog.RuntimeProofBindingTest.*;

class PermissionRuntimeEarlyInitializationTest {
    @Test
    void infrastructureClientLookupDefersTheRepositoryUntilTransactionAdviceIsAvailable() throws Exception {
        try (var context = new AnnotationConfigApplicationContext(Fixture.class)) {
            var snapshots = context.getBean(PermissionRuntimeSnapshotRepository.class);
            assertTrue(AopUtils.isAopProxy(snapshots), "Early infrastructure lookup must not retain an unproxied repository");
            var expected = context.getBean("expectedSnapshot", SystemAuthorizationSnapshot.class);
            var client = context.getBean(EarlyInfrastructure.class).client;

            assertSame(expected, client.fetch("shop", user(), "verified-proof"));

            assertEquals(1, context.getBean(AtomicInteger.class).get());
            assertFalse(TransactionSynchronizationManager.isActualTransactionActive());
        }
    }

    @Configuration(proxyBeanMethods = false)
    @EnableTransactionManagement(proxyTargetClass = true)
    @Import(PermissionRuntimeConfiguration.class)
    static class Fixture {
        @Bean static EarlyInfrastructure earlyInfrastructure(Rbac3AuthorizationClient client) {
            return new EarlyInfrastructure(client);
        }
        @Bean AtomicInteger transactionCount() { return new AtomicInteger(); }
        @Bean PlatformTransactionManager transactionManager(AtomicInteger count) {
            return new AbstractPlatformTransactionManager() {
                @Override protected Object doGetTransaction() { return new Object(); }
                @Override protected void doBegin(Object transaction, org.springframework.transaction.TransactionDefinition definition) { count.incrementAndGet(); }
                @Override protected void doCommit(DefaultTransactionStatus status) { }
                @Override protected void doRollback(DefaultTransactionStatus status) { }
            };
        }
        @Bean("expectedSnapshot") SystemAuthorizationSnapshot expectedSnapshot() { return mock(SystemAuthorizationSnapshot.class); }
        @Bean @Lazy PermissionRuntimeProofService permissionRuntimeProofService() {
            var proofs = mock(PermissionRuntimeProofService.class);
            when(proofs.local(user(), "verified-proof")).thenReturn(new PermissionRuntimeProofService.VerifiedRequest(binding(), ISSUER, user()));
            return proofs;
        }
        @Bean @Lazy PermissionRuntimeSnapshotRepository permissionRuntimeSnapshotRepository(SystemAuthorizationSnapshot expectedSnapshot) {
            var snapshots = mock(PermissionRuntimeSnapshotRepository.class);
            when(snapshots.current(any())).thenAnswer(invocation -> {
                assertTrue(TransactionSynchronizationManager.isActualTransactionActive(), "Local fetch must enter the production @Transactional method");
                return expectedSnapshot;
            });
            return snapshots;
        }
    }

    /** Reproduces a PriorityOrdered infrastructure post-processor requesting the local client before AOP registration. */
    static final class EarlyInfrastructure implements BeanPostProcessor, PriorityOrdered {
        private final Rbac3AuthorizationClient client;
        EarlyInfrastructure(Rbac3AuthorizationClient client) { this.client = client; }
        @Override public int getOrder() { return HIGHEST_PRECEDENCE; }
    }
}
