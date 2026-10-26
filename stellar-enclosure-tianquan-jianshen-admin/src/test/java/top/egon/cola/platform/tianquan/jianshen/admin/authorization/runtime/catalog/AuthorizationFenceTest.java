package top.egon.cola.platform.tianquan.jianshen.admin.authorization.runtime.catalog;

import org.junit.jupiter.api.Test;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.runtime.repository.InitialAuthorizationContextRepository;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.runtime.repository.postgresql.*;
import java.time.*;
import java.util.*;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class AuthorizationFenceTest {
    @Test void expiredWallClockCannotReleaseAnUnpublishedFence() {
        var rows=mock(PostgresqlRuntimeProjectionRepository.class);
        var authority=mock(InitialAuthorizationContextRepository.class);
        var repository=new PostgresqlAuthorizationRuntimeRepository(rows,authority,Clock.fixed(RuntimeProofBindingTest.NOW,ZoneOffset.UTC));
        when(rows.lock(eq("USER"),anyString(),eq("20"))).thenReturn(new PostgresqlRuntimeProjectionRepository.Projection(2,3,Map.of(),false));
        when(rows.read(eq("USER"),anyString(),eq("20"))).thenReturn(Optional.of(new PostgresqlRuntimeProjectionRepository.Projection(2,3,Map.of("fence","mutation"),false)));
        repository.createFence("20","30","mutation",Duration.ofSeconds(1));
        assertTrue(repository.isFenced("20","30"));
        assertThrows(top.egon.cola.platform.tianquan.jianshen.core.rule.Rbac3RuleViolation.class,()->repository.removeFence("20","30"));
        assertThrows(top.egon.cola.platform.tianquan.jianshen.core.rule.Rbac3RuleViolation.class,()->repository.load("20","30"));
        verify(rows).save(eq("USER"),anyString(),eq("20"),eq(2L),eq(3L),eq(Map.of("fence","mutation")),eq(false),eq(RuntimeProofBindingTest.NOW));
    }
    @Test void expiredCheckpointOwnerCannotCompleteAnotherWorkersClaim() {
        var rows=mock(PostgresqlRuntimeProjectionRepository.class);
        var checkpoint=new PostgresqlProjectionCheckpointRepository(rows,Clock.fixed(RuntimeProofBindingTest.NOW,ZoneOffset.UTC));
        when(rows.lock(eq("CHECKPOINT"),anyString(),eq("20"))).thenReturn(new PostgresqlRuntimeProjectionRepository.Projection(0,0,
                Map.of("eventId","event","aggregateVersion",3L,"leaseToken","new-owner","leaseUntil",RuntimeProofBindingTest.NOW.plusSeconds(30).toString()),false));
        assertThrows(IllegalStateException.class,()->checkpoint.completeOwned("20","event","CATALOG","10",3,"old-owner"));
        verify(rows,never()).save(anyString(),anyString(),anyString(),anyLong(),anyLong(),any(),anyBoolean(),any());
    }
}
