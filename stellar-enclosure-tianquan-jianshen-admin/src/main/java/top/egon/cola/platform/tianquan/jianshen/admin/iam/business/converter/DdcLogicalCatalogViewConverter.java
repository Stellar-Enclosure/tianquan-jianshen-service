package top.egon.cola.platform.tianquan.jianshen.admin.iam.business.converter;

import org.mapstruct.Mapper;
import org.mapstruct.Mapping;
import org.mapstruct.ReportingPolicy;
import top.egon.cola.component.common.core.converter.BaseForwardConverter;
import top.egon.cola.component.tianshu.model.management.DdcManagementApp;
import top.egon.cola.component.tianshu.model.management.DdcManagementBiz;
import top.egon.cola.platform.tianquan.jianshen.admin.iam.business.domain.vo.ApplicationCatalogEntry;
import top.egon.cola.platform.tianquan.jianshen.admin.iam.business.domain.vo.BusinessCatalogEntry;

/** One-way projection of the authoritative logical catalog, including disabled parent facts. */
@Mapper(componentModel = "spring", unmappedTargetPolicy = ReportingPolicy.ERROR)
public interface DdcLogicalCatalogViewConverter extends BaseForwardConverter<DdcManagementBiz, BusinessCatalogEntry> {

    @Override
    @Mapping(target = "ddcBusinessId", source = "id")
    BusinessCatalogEntry toTarget(DdcManagementBiz source);

    @Mapping(target = "ddcApplicationId", source = "id")
    @Mapping(target = "ddcBusinessId", source = "businessId")
    @Mapping(target = "applicationEnabled", source = "enabled")
    ApplicationCatalogEntry toApplication(DdcManagementApp source);
}
