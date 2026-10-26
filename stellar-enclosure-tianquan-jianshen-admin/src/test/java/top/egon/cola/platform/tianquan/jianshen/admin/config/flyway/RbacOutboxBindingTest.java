package top.egon.cola.platform.tianquan.jianshen.admin.config.flyway;

import javax.sql.DataSource;
import org.apache.ibatis.mapping.Environment;
import org.apache.ibatis.session.SqlSessionFactory;
import org.junit.jupiter.api.Test;
import org.mybatis.spring.transaction.SpringManagedTransactionFactory;
import org.springframework.orm.jpa.JpaTransactionManager;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class RbacOutboxBindingTest {
    @Test void JpaAndOutboxMustShareTheSameDatasourceObject() {
        var source=mock(DataSource.class); var other=mock(DataSource.class);
        var jpa=new JpaTransactionManager(); jpa.setDataSource(source);
        var factory=mock(SqlSessionFactory.class);
        var config=new org.apache.ibatis.session.Configuration(new Environment("test",new SpringManagedTransactionFactory(),source));
        when(factory.getConfiguration()).thenReturn(config);
        assertDoesNotThrow(()->Rbac3FlywayConfiguration.requireTransactionBinding(source,jpa,factory));
        config.setEnvironment(new Environment("test",new SpringManagedTransactionFactory(),other));
        assertThrows(IllegalStateException.class,()->Rbac3FlywayConfiguration.requireTransactionBinding(source,jpa,factory));
    }
    @Test void RetiredOutboxMigrationHasNoHostBean() throws Exception {
        assertNull(Rbac3FlywayConfiguration.class.getMethod("buildOutboxFlyway",DataSource.class)
                .getAnnotation(org.springframework.context.annotation.Bean.class));
        assertTrue(java.util.Arrays.stream(Rbac3FlywayConfiguration.class.getDeclaredMethods())
                .map(method->method.getAnnotation(org.springframework.context.annotation.Bean.class))
                .filter(java.util.Objects::nonNull).flatMap(bean->java.util.Arrays.stream(bean.value()))
                .noneMatch(Rbac3FlywayConfiguration.OUTBOX_FLYWAY::equals));
    }
}
