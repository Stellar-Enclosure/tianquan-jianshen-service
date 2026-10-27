package top.egon.cola.platform.tianquan.jianshen.admin.registration.catalog.service;

import jakarta.persistence.EntityManager;
import jakarta.persistence.Query;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import org.junit.jupiter.api.Test;
import top.egon.cola.platform.tianquan.jianshen.admin.registration.catalog.domain.convertor.PermissionCatalogJson;
import top.egon.cola.platform.tianquan.jianshen.admin.registration.catalog.repository.PermissionCatalogScopeRepository;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;
import static top.egon.cola.platform.tianquan.jianshen.admin.registration.catalog.service.PermissionCatalogFixture.SCOPE;

class PermissionCatalogReplicaScopeTest {
    @Test
    void replicaOwnerReadsKeepScopeBindingButDoNotLockBusinessRows() {
        var entityManager = mock(EntityManager.class);
        var json = mock(PermissionCatalogJson.class);
        var scope = mock(Query.class, RETURNS_SELF);
        var pointer = mock(Query.class, RETURNS_SELF);
        var owner = mock(Query.class, RETURNS_SELF);
        when(entityManager.createNativeQuery(anyString())).thenReturn(scope, pointer, owner);
        when(scope.getResultList()).thenReturn(Collections.singletonList(new Object[] {1L, 10L, "biz", "app", "default", "test", 20L}));
        when(pointer.getResultList()).thenReturn(Collections.singletonList(new Object[] {2L, 3L}));
        when(owner.getResultList()).thenReturn(Collections.singletonList(new Object[] {"JAVA", "[]", "[]", "[]", "[]", 4L, 5L}));
        when(json.strings("[]")).thenReturn(List.of());
        var repository = new PermissionCatalogScopeRepository(entityManager, json);

        var found = repository.readExistingOwner(SCOPE, "api");

        assertEquals(20L, found.applicationId());
        assertEquals(2L, found.activeRevision());
        assertEquals(4L, found.producerRevision());
        var sql = org.mockito.ArgumentCaptor.forClass(String.class);
        verify(entityManager, times(3)).createNativeQuery(sql.capture());
        assertTrue(sql.getAllValues().stream().noneMatch(value -> value.toLowerCase(Locale.ROOT).contains("for update")));
        verify(scope).setParameter("scope", 1L);
        verify(owner).setParameter("scope", 1L);
        verify(owner).setParameter("producer", "api");
        verify(owner).setParameter("enabledOnly", false);
    }
}
