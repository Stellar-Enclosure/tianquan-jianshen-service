package top.egon.cola.platform.tianquan.jianshen.admin.iam.business.service;

import org.junit.jupiter.api.Test;
import org.mapstruct.factory.Mappers;
import top.egon.cola.component.tianshu.api.catalog.DdcLogicalCatalogClient;
import top.egon.cola.component.tianshu.api.catalog.HttpDdcLogicalCatalogClient.CatalogFailureCodeEnum;
import top.egon.cola.component.tianshu.api.catalog.HttpDdcLogicalCatalogClient.DdcLogicalCatalogException;
import top.egon.cola.component.tianshu.model.management.DdcManagementApp;
import top.egon.cola.component.tianshu.model.management.DdcManagementBiz;
import top.egon.cola.platform.tianquan.jianshen.admin.iam.business.converter.DdcLogicalCatalogViewConverter;
import top.egon.cola.platform.tianquan.jianshen.admin.iam.business.domain.vo.ApplicationCatalogEntry;
import top.egon.cola.platform.tianquan.jianshen.admin.iam.business.domain.vo.BusinessCatalogEntry;
import top.egon.cola.platform.tianquan.jianshen.core.rule.Rbac3RuleViolation;

import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

class HttpDdcCatalogGatewayTest {

    private final DdcLogicalCatalogViewConverter converter = Mappers.getMapper(DdcLogicalCatalogViewConverter.class);

    @Test
    void usesTheLogicalHttpSdkContract() throws Exception {
        assertThat(HttpDdcCatalogGateway.class.getConstructor(DdcLogicalCatalogClient.class, DdcLogicalCatalogViewConverter.class)).isNotNull();
        assertThat(top.egon.cola.component.common.core.converter.BaseForwardConverter.class.isAssignableFrom(converter.getClass())).isTrue();
    }

    @Test
    void mapsApplicationWithParentBusinessFactsUsingRealGeneratedConverter() {
        var client = mock(DdcLogicalCatalogClient.class);
        when(client.findApplication("tianshu-app-1")).thenReturn(Optional.of(
                new DdcManagementApp("tianshu-app-1", "tianshu-biz-1", "orders", "console", "Console", true, false)));
        assertThat(gateway(client).findApplication("tianshu-app-1")).contains(new ApplicationCatalogEntry(
                "tianshu-app-1", "tianshu-biz-1", "orders", "console", "Console", true, false));
        verify(client).findApplication("tianshu-app-1");
    }

    @Test
    void mapsBusinessCatalogAndDelegatesNormalizedReadOnlyQuery() {
        var client = mock(DdcLogicalCatalogClient.class);
        when(client.listBusinesses("order")).thenReturn(List.of(new DdcManagementBiz("tianshu-biz-1", "orders", "Orders", false)));
        assertThat(gateway(client).listBusinesses(" order ")).containsExactly(new BusinessCatalogEntry("tianshu-biz-1", "orders", "Orders", false));
        verify(client).listBusinesses("order");
    }

    @Test
    void preservesAbsentBusinessAndApplicationAsEmptyOptionals() {
        var client = mock(DdcLogicalCatalogClient.class);
        when(client.findBusiness("missing")).thenReturn(Optional.empty());
        when(client.findApplication("missing")).thenReturn(Optional.empty());
        assertThat(gateway(client).findBusiness("missing")).isEmpty();
        assertThat(gateway(client).findApplication("missing")).isEmpty();
    }

    @Test
    void preservesHistoricalOpaqueBusinessIdentityAndAllApplicationListFacts() {
        var client = mock(DdcLogicalCatalogClient.class);
        var business = new DdcManagementBiz("legacy-business-public-id", "orders", "Orders", true);
        var app = new DdcManagementApp("legacy-app-public-id", business.id(), "orders", "console", "Console", false, true);
        when(client.findBusiness(business.id())).thenReturn(Optional.of(business));
        when(client.listApplications(business.id(), "研发 & 财务+")).thenReturn(List.of(app));
        assertThat(gateway(client).findBusiness(business.id())).contains(new BusinessCatalogEntry(business.id(), "orders", "Orders", true));
        assertThat(gateway(client).listApplications(" " + business.id() + " ", " 研发 & 财务+ "))
                .containsExactly(new ApplicationCatalogEntry(app.id(), business.id(), "orders", "console", "Console", false, true));
        verify(client).listApplications(business.id(), "研发 & 财务+");
    }

    @Test
    void blankPointLookupsRemainLocalMissesAndBlankListFiltersRemainAbsent() {
        var client = mock(DdcLogicalCatalogClient.class);
        for (String blank : java.util.Arrays.asList(null, "", " ")) {
            assertThat(gateway(client).findBusiness(blank)).isEmpty();
            assertThat(gateway(client).findApplication(blank)).isEmpty();
        }
        verifyNoInteractions(client);
        when(client.listBusinesses(null)).thenReturn(List.of());
        when(client.listApplications(null, null)).thenReturn(List.of());
        assertThat(gateway(client).listBusinesses(" ")).isEmpty();
        assertThat(gateway(client).listApplications(" ", " ")).isEmpty();
        verify(client).listBusinesses(null);
        verify(client).listApplications(null, null);
    }

    @Test
    void mapsAllSdkDenialsAndUnavailableStatesWithoutTurningThemIntoMissingRows() {
        for (var code : CatalogFailureCodeEnum.values()) {
            var failure = mock(DdcLogicalCatalogException.class);
            when(failure.code()).thenReturn(code);
            String reason = switch (code) {
                case UNAUTHENTICATED -> "SERVICE_IDENTITY_DENIED";
                case PERMISSION_DENIED -> "PERMISSION_DENIED";
                case UNAVAILABLE, INVALID_RESPONSE -> "DIRECTORY_RUNTIME_UNAVAILABLE";
            };
            assertAllReadsReject(failure, reason);
        }
    }

    @Test
    void invalidInputAndUnknownClientFailureRemainSanitizedAndFailClosed() {
        assertAllReadsReject(new IllegalArgumentException("sensitive input detail"), "REQUEST_INVALID");
        assertAllReadsReject(new IllegalStateException("sensitive backend detail"), "DIRECTORY_RUNTIME_UNAVAILABLE");
    }

    @Test
    void missingOptionalNullListsAndNullRowsNeverBecomeEmptySuccess() {
        var client = mock(DdcLogicalCatalogClient.class);
        when(client.findBusiness("biz")).thenReturn(null);
        when(client.findApplication("app")).thenReturn(null);
        when(client.listBusinesses(null)).thenReturn(null);
        when(client.listApplications(null, null)).thenReturn(null);
        var gateway = gateway(client);
        rejected("DIRECTORY_RUNTIME_UNAVAILABLE", () -> gateway.findBusiness("biz"));
        rejected("DIRECTORY_RUNTIME_UNAVAILABLE", () -> gateway.findApplication("app"));
        rejected("DIRECTORY_RUNTIME_UNAVAILABLE", () -> gateway.listBusinesses(null));
        rejected("DIRECTORY_RUNTIME_UNAVAILABLE", () -> gateway.listApplications(null, null));
        when(client.listBusinesses(null)).thenReturn(java.util.Collections.singletonList(null));
        when(client.listApplications(null, null)).thenReturn(java.util.Collections.singletonList(null));
        rejected("DIRECTORY_RUNTIME_UNAVAILABLE", () -> gateway.listBusinesses(null));
        rejected("DIRECTORY_RUNTIME_UNAVAILABLE", () -> gateway.listApplications(null, null));
    }

    @Test
    void preservesAnAlreadySanitizedLocalAuthorityDenial() {
        assertAllReadsReject(new Rbac3RuleViolation("PERMISSION_DENIED"), "PERMISSION_DENIED");
    }

    private HttpDdcCatalogGateway gateway(DdcLogicalCatalogClient client) { return new HttpDdcCatalogGateway(client, converter); }

    private void assertAllReadsReject(RuntimeException failure, String reason) {
        var client = mock(DdcLogicalCatalogClient.class);
        when(client.findBusiness("biz")).thenThrow(failure);
        when(client.findApplication("app")).thenThrow(failure);
        when(client.listBusinesses("orders")).thenThrow(failure);
        when(client.listApplications("biz", "console")).thenThrow(failure);
        var gateway = gateway(client);
        rejected(reason, () -> gateway.findBusiness("biz"));
        rejected(reason, () -> gateway.findApplication("app"));
        rejected(reason, () -> gateway.listBusinesses("orders"));
        rejected(reason, () -> gateway.listApplications("biz", "console"));
    }

    private static void rejected(String reason, Runnable operation) {
        assertThatThrownBy(operation::run).isInstanceOfSatisfying(Rbac3RuleViolation.class, failure -> {
            assertThat(failure.reasonCode()).isEqualTo(reason);
            assertThat(failure.getMessage()).isEqualTo(reason);
            assertThat(failure.getCause()).isNull();
        });
    }
}
