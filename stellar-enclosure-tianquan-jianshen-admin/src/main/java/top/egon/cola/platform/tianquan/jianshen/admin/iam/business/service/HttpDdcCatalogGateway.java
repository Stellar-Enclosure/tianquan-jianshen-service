package top.egon.cola.platform.tianquan.jianshen.admin.iam.business.service;

import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Qualifier;
import top.egon.cola.component.tianshu.api.catalog.DdcLogicalCatalogClient;
import top.egon.cola.component.tianshu.api.catalog.HttpDdcLogicalCatalogClient.DdcLogicalCatalogException;
import top.egon.cola.platform.tianquan.jianshen.admin.iam.business.converter.DdcLogicalCatalogViewConverter;
import top.egon.cola.platform.tianquan.jianshen.admin.iam.business.domain.vo.ApplicationCatalogEntry;
import top.egon.cola.platform.tianquan.jianshen.admin.iam.business.domain.vo.BusinessCatalogEntry;
import top.egon.cola.platform.tianquan.jianshen.admin.iam.business.repository.DdcCatalogGateway;
import top.egon.cola.platform.tianquan.jianshen.core.rule.Rbac3RuleViolation;

import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.function.Supplier;

/** Read-only HTTP logical catalog adapter. The application configuration owns the shared SDK lifecycle. */
@Slf4j
@RequiredArgsConstructor
public final class HttpDdcCatalogGateway implements DdcCatalogGateway {

    @NonNull @Qualifier("ddcLogicalCatalogClient") private final DdcLogicalCatalogClient client;
    @NonNull @Qualifier("ddcLogicalCatalogViewConverterImpl") private final DdcLogicalCatalogViewConverter converter;

    @Override
    public Optional<BusinessCatalogEntry> findBusiness(String ddcBusinessId) {
        if (isBlank(ddcBusinessId)) { return Optional.empty(); }
        return read(() -> client.findBusiness(ddcBusinessId).map(converter::toTarget));
    }

    @Override
    public List<BusinessCatalogEntry> listBusinesses(String keyword) {
        return read(() -> requiredRows(client.listBusinesses(normalize(keyword))).stream()
                .map(converter::toTarget).toList());
    }

    @Override
    public Optional<ApplicationCatalogEntry> findApplication(String ddcApplicationId) {
        if (isBlank(ddcApplicationId)) { return Optional.empty(); }
        return read(() -> client.findApplication(ddcApplicationId).map(converter::toApplication));
    }

    @Override
    public List<ApplicationCatalogEntry> listApplications(String ddcBusinessId, String keyword) {
        return read(() -> requiredRows(client.listApplications(normalize(ddcBusinessId), normalize(keyword))).stream()
                .map(converter::toApplication).toList());
    }

    private static <T> List<T> requiredRows(List<T> rows) {
        Objects.requireNonNull(rows, "catalog result");
        rows.forEach(row -> Objects.requireNonNull(row, "catalog row"));
        return rows;
    }

    private static <T> T read(Supplier<T> operation) {
        try {
            return Objects.requireNonNull(operation.get(), "catalog result");
        } catch (DdcLogicalCatalogException failure) {
            throw new Rbac3RuleViolation(switch (failure.code()) {
                case UNAUTHENTICATED -> "SERVICE_IDENTITY_DENIED";
                case PERMISSION_DENIED -> "PERMISSION_DENIED";
                case UNAVAILABLE, INVALID_RESPONSE -> "DIRECTORY_RUNTIME_UNAVAILABLE";
            });
        } catch (Rbac3RuleViolation rejected) {
            throw rejected;
        } catch (IllegalArgumentException invalid) {
            throw new Rbac3RuleViolation("REQUEST_INVALID");
        } catch (RuntimeException unavailable) {
            throw new Rbac3RuleViolation("DIRECTORY_RUNTIME_UNAVAILABLE");
        }
    }

    private static String normalize(String value) { return isBlank(value) ? null : value.trim(); }
    private static boolean isBlank(String value) { return value == null || value.isBlank(); }
}
