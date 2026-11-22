package top.egon.cola.platform.tianquan.jianshen.admin.iam.role;

import top.egon.cola.component.common.id.snowflake.SnowflakeIdGenerator;
import jakarta.persistence.EntityManager;
import jakarta.persistence.LockModeType;
import jakarta.persistence.TypedQuery;
import org.mapstruct.factory.Mappers;
import top.egon.cola.platform.tianquan.jianshen.admin.iam.role.converter.RoleEditDetailConverter;
import top.egon.cola.platform.tianquan.jianshen.admin.iam.role.domain.po.RolePO;
import top.egon.cola.platform.tianquan.jianshen.admin.iam.role.domain.vo.RoleEditDetailVO;
import top.egon.cola.platform.tianquan.jianshen.admin.iam.role.domain.enums.RoleRiskLevelEnum;
import top.egon.cola.platform.tianquan.jianshen.admin.iam.role.domain.enums.RoleStatusEnum;
import top.egon.cola.platform.tianquan.jianshen.admin.iam.role.domain.enums.RoleTypeEnum;
import top.egon.cola.platform.tianquan.jianshen.admin.iam.role.domain.dto.UpdateRoleCommandDTO;
import static org.mockito.Mockito.verifyNoInteractions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.BeforeAll;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.runtime.state.repository.TenantAuthorizationStateRepository;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.grant.roleinheritance.repository.jdbc.PostgresqlRoleClosureRepository;
import top.egon.cola.platform.tianquan.jianshen.admin.iam.role.repository.jpa.JpaRoleRepository;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.runtime.repository.AuthorizationEventPublisher;
import top.egon.cola.platform.tianquan.jianshen.admin.shared.domain.DatabaseClock;
import top.egon.cola.platform.tianquan.jianshen.admin.iam.role.service.RoleFacade;
import top.egon.cola.platform.tianquan.jianshen.core.hierarchy.RoleHierarchy;
import java.time.Instant;
import java.time.Duration;
import java.util.List;
import java.util.function.Function;
import static org.junit.jupiter.api.Assertions.assertEquals;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.grant.roleinheritance.repository.RoleHierarchyRepository;
import top.egon.cola.platform.tianquan.jianshen.admin.iam.role.repository.RoleControlRepository;
import top.egon.cola.platform.tianquan.jianshen.admin.iam.role.domain.dto.CreateRoleCommandDTO;
import top.egon.cola.platform.tianquan.jianshen.admin.iam.role.domain.vo.RoleMutationResultVO;
import top.egon.cola.platform.tianquan.jianshen.admin.authorization.grant.roleinheritance.domain.dto.InheritanceCommandDTO;
import top.egon.cola.platform.tianquan.jianshen.core.hierarchy.RoleNode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class RoleControlFacadeTest {

    @BeforeAll
    static void bindTheProcessWideEngine() {
        SnowflakeIdGenerator.initialize(0L, Duration.ofMillis(5));
    }

    @Test
    void graphMutationPublishesTheVersionReturnedByAuthorizationState() {
        EntityManager entityManager = mock(EntityManager.class);
        PostgresqlRoleClosureRepository closureStore = mock(
                PostgresqlRoleClosureRepository.class);
        DatabaseClock databaseClock = mock(DatabaseClock.class);
        AuthorizationEventPublisher eventPort = mock(AuthorizationEventPublisher.class);
        TenantAuthorizationStateRepository stateStore = mock(
                TenantAuthorizationStateRepository.class);
        when(databaseClock.transactionNow()).thenReturn(Instant.EPOCH);
        when(stateStore.increment(10001L, "actor")).thenReturn(4L);
        when(eventPort.enqueue(any())).thenReturn("event-2");

        new JpaRoleRepository(
                entityManager,
                closureStore,
                databaseClock,
                eventPort,
                stateStore, Mappers.getMapper(RoleEditDetailConverter.class)).recordGraphMutation(
                "10001", "71001", new top.egon.cola.platform.tianquan.jianshen.core.hierarchy.RoleEdge(
                        "50001", "50002"), true, "actor");

        verify(stateStore).increment(10001L, "actor");
        verify(eventPort).enqueue(any());
    }

    @Test
    void roleQueriesRemainAtTheRoleControlBoundary() {
        RecordingControlStore controlStore = new RecordingControlStore();
        RoleFacade facade = new RoleFacade(new EmptyHierarchyStore(), controlStore);
        assertEquals(List.of(), facade.roles("10001", "71001"));
    }

    @Test
    void roleInheritanceRejectsRolesOutsideTheLocalApplication() {
        RoleFacade facade = new RoleFacade(new ApplicationScopedHierarchyStore());

        assertThatThrownBy(() -> facade.addInheritance(new InheritanceCommandDTO(
                "10001", "71001", "50001", "50002", -1L, "actor")))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("same local application");
    }

    @Test
    @SuppressWarnings("unchecked")
    void roleDetailBindsTenantAndIdAndProjectsWithoutPublishing() {
        EntityManager entityManager = mock(EntityManager.class);
        TypedQuery<RolePO> query = mock(TypedQuery.class);
        var events = mock(AuthorizationEventPublisher.class);
        var state = mock(TenantAuthorizationStateRepository.class);
        when(entityManager.createQuery(
                "select r from RoleEntity r where r.id = :roleId and r.tenantId = :tenantId", RolePO.class))
                .thenReturn(query);
        when(query.setParameter("roleId", 3801L)).thenReturn(query);
        when(query.setParameter("tenantId", 10L)).thenReturn(query);
        RolePO row = mock(RolePO.class);
        when(row.getId()).thenReturn(3801L);
        when(row.getApplicationId()).thenReturn(20L);
        when(row.getRoleName()).thenReturn("仓库运营");
        when(row.getStatus()).thenReturn(RoleStatusEnum.ACTIVE);
        when(row.getLandingRouteId()).thenReturn(null);
        when(row.getLandingPriority()).thenReturn(10);
        when(row.getMaximumAssignmentDays()).thenReturn(45);
        when(row.getVersion()).thenReturn(7L);
        when(query.getSingleResultOrNull()).thenReturn(row, (RolePO) null);
        var repository = new JpaRoleRepository(entityManager, mock(PostgresqlRoleClosureRepository.class),
                mock(DatabaseClock.class), events, state, Mappers.getMapper(RoleEditDetailConverter.class));
        var facade = new RoleFacade(repository, repository);
        assertEquals(new RoleEditDetailVO("3801", "20", "仓库运营", "ACTIVE", null, 10, 45, 7),
                facade.roleEditDetail("10", 3801L));
        assertThatThrownBy(() -> facade.roleEditDetail("10", 3801L))
                .hasMessageContaining("RESOURCE_NOT_FOUND");
        verifyNoInteractions(events, state);
    }

    @Test
    void roleDetailCanRoundTripOriginalConfigurationThroughTheExistingUpdate() {
        var entityManager = mock(EntityManager.class);
        var clock = mock(DatabaseClock.class);
        var events = mock(AuthorizationEventPublisher.class);
        var state = mock(TenantAuthorizationStateRepository.class);
        var row = new RolePO(3801L, 10L, 20L, "WAREHOUSE", "仓库运营",
                RoleTypeEnum.POSITION, RoleRiskLevelEnum.LOW, false, 8201L, 10, 45, "actor", Instant.EPOCH);
        when(entityManager.find(RolePO.class, 3801L, LockModeType.PESSIMISTIC_WRITE)).thenReturn(row);
        when(clock.transactionNow()).thenReturn(Instant.EPOCH.plusSeconds(1));
        when(events.enqueue(any())).thenReturn("propagation-accepted");
        var converter = Mappers.getMapper(RoleEditDetailConverter.class);
        var repository = new JpaRoleRepository(entityManager, mock(PostgresqlRoleClosureRepository.class),
                clock, events, state, converter);
        var facade = new RoleFacade(repository, repository);
        var detail = converter.toTarget(row);

        facade.updateRole(new UpdateRoleCommandDTO("10", detail.roleId(), "仓库运营二组", detail.status(),
                detail.landingRouteId(), detail.landingPriority(), detail.maximumAssignmentDays(), detail.version(),
                "actor"), Instant.EPOCH);

        assertEquals(new RoleEditDetailVO("3801", "20", "仓库运营二组", "ACTIVE",
                "8201", 10, 45, detail.version()), converter.toTarget(row));
        assertThatThrownBy(() -> facade.updateRole(new UpdateRoleCommandDTO("10", "3801", "未提交名称", "ACTIVE",
                null, 0, null, detail.version() + 1, "actor"), Instant.EPOCH))
                .hasMessageContaining("RESOURCE_VERSION_CONFLICT");
        assertEquals("8201", converter.toTarget(row).landingRouteId());
    }

    private static final class RecordingControlStore implements RoleControlRepository {

        @Override
        public RoleEditDetailVO roleEditDetail(long tenantId, long roleId) {
            throw new UnsupportedOperationException();
        }


        @Override
        public RoleMutationResultVO create(
                CreateRoleCommandDTO command,
                Instant now) {
            throw new UnsupportedOperationException();
        }

        @Override
        public List<top.egon.cola.platform.tianquan.jianshen.admin.iam.role.domain.vo.RoleVO> roles(
                String tenantId,
                String applicationId) {
            return List.of();
        }
    }

    private static class EmptyHierarchyStore implements RoleHierarchyRepository {

        @Override
        public <T> T withGraphLock(
                String tenantId,
                String applicationId,
                Function<RoleHierarchy, T> action) {
            return action.apply(new RoleHierarchy(List.of(), List.of()));
        }

        @Override
        public void addEdge(String tenantId, String applicationId,
                            top.egon.cola.platform.tianquan.jianshen.core.hierarchy.RoleEdge edge) {
        }

        @Override
        public void removeEdge(String tenantId, String applicationId,
                               top.egon.cola.platform.tianquan.jianshen.core.hierarchy.RoleEdge edge) {
        }

        @Override
        public void rebuildClosure(String tenantId, String applicationId) {
        }
    }

    private static final class ApplicationScopedHierarchyStore extends EmptyHierarchyStore {

        @Override
        public <T> T withGraphLock(
                String tenantId,
                String applicationId,
                Function<RoleHierarchy, T> action) {
            return action.apply(new RoleHierarchy(List.of(
                    new RoleNode("50001", "71001", "SENIOR", true,
                            RoleNode.RiskLevel.LOW, false, null, 0),
                    new RoleNode("50002", "71002", "JUNIOR", true,
                            RoleNode.RiskLevel.LOW, false, null, 0)), List.of()));
        }
    }
}
