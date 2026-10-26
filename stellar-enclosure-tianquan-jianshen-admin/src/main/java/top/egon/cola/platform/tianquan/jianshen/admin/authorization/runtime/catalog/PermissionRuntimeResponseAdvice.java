package top.egon.cola.platform.tianquan.jianshen.admin.authorization.runtime.catalog;

import org.springframework.core.MethodParameter;
import org.springframework.http.MediaType;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.http.server.ServerHttpRequest;
import org.springframework.http.server.ServerHttpResponse;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.servlet.mvc.method.annotation.ResponseBodyAdvice;

/** Fresh database policy/permission views are never reusable by an intermediary cache. */
@RestControllerAdvice(basePackages="top.egon.cola.platform.tianquan.jianshen.admin.authorization.runtime")
public class PermissionRuntimeResponseAdvice implements ResponseBodyAdvice<Object> {
    @Override public boolean supports(MethodParameter method, Class<? extends HttpMessageConverter<?>> converter) { return true; }
    @Override public Object beforeBodyWrite(Object body, MethodParameter method, MediaType contentType,
            Class<? extends HttpMessageConverter<?>> converter, ServerHttpRequest request, ServerHttpResponse response) {
        response.getHeaders().setCacheControl("no-store"); return body;
    }
}
