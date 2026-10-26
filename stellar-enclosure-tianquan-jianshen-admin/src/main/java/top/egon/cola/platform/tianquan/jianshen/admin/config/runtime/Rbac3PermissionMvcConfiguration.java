package top.egon.cola.platform.tianquan.jianshen.admin.config.runtime;

import org.springframework.context.annotation.Configuration;
import org.springframework.http.MediaType;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.http.converter.json.MappingJackson2HttpMessageConverter;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;
import top.egon.cola.platform.tianquan.jianshen.starter.field.PermissionJsonMapperFactory;
import java.util.List;

/** HTTP-only field enforcement; the shared persistence and control-plane codecs are never mutated. */
@Configuration(proxyBeanMethods=false)
@org.springframework.core.annotation.Order(org.springframework.core.Ordered.LOWEST_PRECEDENCE)
@org.springframework.boot.autoconfigure.condition.ConditionalOnProperty(prefix="egon.cola.platform.tianquan.jianshen", name="enabled", havingValue="true")
public class Rbac3PermissionMvcConfiguration implements WebMvcConfigurer {
    private final PermissionJsonMapperFactory fields;
    private final com.fasterxml.jackson.databind.ObjectMapper transportMapper;

    public Rbac3PermissionMvcConfiguration(PermissionJsonMapperFactory fields,
            @org.springframework.beans.factory.annotation.Qualifier("jacksonObjectMapper") com.fasterxml.jackson.databind.ObjectMapper transportMapper) {
        this.fields = fields; this.transportMapper = transportMapper;
    }

    @Override
    public void extendMessageConverters(List<HttpMessageConverter<?>> converters) {
        var preferred = converters.stream().filter(MappingJackson2HttpMessageConverter.class::isInstance)
                .map(MappingJackson2HttpMessageConverter.class::cast).findFirst()
                .orElseGet(() -> new MappingJackson2HttpMessageConverter(transportMapper));
        int jsonSlot = java.util.stream.IntStream.range(0, converters.size())
                .filter(index -> converters.get(index).canRead(java.util.Map.class, MediaType.APPLICATION_JSON)
                        || converters.get(index).canWrite(java.util.Map.class, MediaType.APPLICATION_JSON))
                .findFirst().orElse(converters.size());
        int current = converters.indexOf(preferred);
        // Replace the first general JSON choice without preceding String, byte or streaming converters.
        if (current < 0) converters.add(jsonSlot, preferred);
        else if (current > jsonSlot) { converters.remove(current); converters.add(jsonSlot, preferred); }
        for (HttpMessageConverter<?> converter : converters) {
            if (converter instanceof MappingJackson2HttpMessageConverter json) {
                json.setObjectMapper(fields.forTransport(json.getObjectMapper()));
            }
        }
    }
}
