package top.egon.cola.platform.tianquan.jianshen.admin.authorization.runtime.service;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import org.junit.jupiter.api.Test;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.runtime.domain.dto.MutationWorkDTO;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.runtime.domain.vo.ExpectedVersionsVO;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.runtime.domain.vo.MutationScopeVO;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.runtime.repository.AuthorizationMutationRecoveryRepository;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.runtime.repository.AuthorizationMutationRepository;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.runtime.repository.RuntimeProjector;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

class AuthorizationMutationOwnershipTest {
    private static final Clock CLOCK = Clock.fixed(Instant.parse("2026-10-28T00:00:00Z"), ZoneOffset.UTC);
    private static final MutationScopeVO SCOPE = new MutationScopeVO("7", "USER", "9", "command", "actor");
    private static final ExpectedVersionsVO VERSIONS = new ExpectedVersionsVO(1L, 2L, 1L, 1L);

    @Test
    void coordinatorLosingItsClaimCannotCreateALateFence() {
        var store = mock(AuthorizationMutationRepository.class);
        var guards = mock(AuthorizationPublicationGuardService.class);
        var projector = mock(RuntimeProjector.class);
        when(store.claimInitial(eq("7"), eq("42"), anyString())).thenReturn(true);
        when(store.runClaimed(eq("7"), eq("42"), anyString(), any(), any(), eq("actor"))).thenReturn(false);
        var coordinator = new AuthorizationMutationCoordinator(store, guards, projector,
                work -> work.get(), () -> "42", CLOCK);

        var result = coordinator.execute(SCOPE, "subject", VERSIONS, () -> "changed");

        assertThat(result.completed()).isFalse();
        assertThat(result.reasonCode()).isEqualTo("AUTH_PROPAGATION_PENDING");
        verifyNoInteractions(guards, projector);
        verify(store, never()).failClaimed(anyString(), anyString(), anyString(), anyString(), any(), anyString());
    }

    @Test
    void coordinatorCarriesOneClaimThroughProjectionAndTransitions() {
        var store = mock(AuthorizationMutationRepository.class);
        var guards = mock(AuthorizationPublicationGuardService.class);
        var projector = mock(RuntimeProjector.class);
        when(store.claimInitial(eq("7"), eq("42"), anyString())).thenReturn(true);
        when(store.runClaimed(eq("7"), eq("42"), anyString(), any(), any(), eq("actor"))).thenAnswer(call -> {
            call.<Runnable>getArgument(3).run();
            return true;
        });
        var coordinator = new AuthorizationMutationCoordinator(store, guards, projector,
                work -> work.get(), () -> "42", CLOCK);

        var result = coordinator.execute(SCOPE, "subject", VERSIONS, () -> "changed");

        assertThat(result.completed()).isTrue();
        var owner = org.mockito.ArgumentCaptor.forClass(String.class);
        verify(store).claimInitial(eq("7"), eq("42"), owner.capture());
        verify(store).runClaimed(eq("7"), eq("42"), eq(owner.getValue()), any(), any(), eq("actor"));
        verify(store, times(2)).transitionClaimed(eq("7"), eq("42"), eq(owner.getValue()), any(), any());
        verify(guards).create("7", "USER", "9", "42");
        verify(guards).release("7", "USER", "9");
        verify(projector).project(any());
    }

    @Test
    void initialClaimFailureRollsBackBusinessMutation() {
        var store = mock(AuthorizationMutationRepository.class);
        var manager = mock(org.springframework.transaction.PlatformTransactionManager.class);
        when(manager.getTransaction(any())).thenReturn(new org.springframework.transaction.support.SimpleTransactionStatus());
        var transaction = new org.springframework.transaction.support.TransactionTemplate(manager);
        var coordinator = new AuthorizationMutationCoordinator(store, mock(AuthorizationPublicationGuardService.class),
                mock(RuntimeProjector.class), work -> transaction.execute(status -> work.get()), () -> "42", CLOCK);

        assertThatThrownBy(() -> coordinator.execute(SCOPE, "subject", VERSIONS, () -> "changed"))
                .hasMessageContaining("could not be claimed");
        verify(manager).rollback(any());
    }

    @Test
    void staleRecoveryOwnerDoesNotProjectOrMarkAFailure() {
        var store = mock(AuthorizationMutationRecoveryRepository.class);
        var projector = mock(RuntimeProjectionExecutor.class);
        var candidate = new MutationWorkDTO("42", "7", "USER", "9", "RECOVERY_REQUIRED", "old-owner");
        when(store.claimRecoverable(5)).thenReturn(List.of(candidate));
        when(store.runClaimed(eq("7"), eq("42"), eq("old-owner"), any(), any(), anyString())).thenReturn(false);
        var service = new AuthorizationMutationRecoveryService(store, projector, CLOCK, 5);

        assertThat(service.runOnce()).isZero();
        verifyNoInteractions(projector);
        verify(store, never()).failClaimed(anyString(), anyString(), anyString(), anyString(), any(), anyString());
    }
}
