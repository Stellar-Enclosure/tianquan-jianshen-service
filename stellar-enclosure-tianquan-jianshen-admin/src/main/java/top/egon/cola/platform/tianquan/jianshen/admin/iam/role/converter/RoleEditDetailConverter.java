package top.egon.cola.platform.tianquan.jianshen.admin.iam.role.converter;

import org.mapstruct.Mapper;
import org.mapstruct.Mapping;
import org.mapstruct.ReportingPolicy;
import top.egon.cola.component.common.core.converter.BaseForwardConverter;
import top.egon.cola.platform.tianquan.jianshen.admin.iam.role.domain.po.RolePO;
import top.egon.cola.platform.tianquan.jianshen.admin.iam.role.domain.vo.RoleEditDetailVO;

@Mapper(componentModel = "spring", unmappedTargetPolicy = ReportingPolicy.ERROR)
public interface RoleEditDetailConverter extends BaseForwardConverter<RolePO, RoleEditDetailVO> {

    @Override
    @Mapping(target = "roleId", source = "id")
    RoleEditDetailVO toTarget(RolePO source);
}
