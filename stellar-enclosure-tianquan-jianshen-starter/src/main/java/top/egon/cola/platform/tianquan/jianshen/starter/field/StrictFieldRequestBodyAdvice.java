package top.egon.cola.platform.tianquan.jianshen.starter.field;

import org.springframework.core.MethodParameter;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpInputMessage;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.servlet.mvc.method.annotation.RequestBodyAdviceAdapter;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Type;
import java.util.Objects;

/**
 * Intercepts {@code @RequestBody} parameters annotated with {@link StrictFieldBinding}
 * so controllers do not manually read {@code HttpServletRequest} or re-serialize JSON
 * to construct {@link SubmittedFieldSet}.
 */
@RestControllerAdvice
public class StrictFieldRequestBodyAdvice extends RequestBodyAdviceAdapter {

    private final StrictSubmittedFieldBinder binder;

    public StrictFieldRequestBodyAdvice(StrictSubmittedFieldBinder binder) {
        this.binder = Objects.requireNonNull(binder, "binder");
    }

    @Override
    public boolean supports(
            MethodParameter methodParameter,
            Type targetType,
            Class<? extends HttpMessageConverter<?>> converterType) {
        return binding(methodParameter) != null;
    }

    @Override
    public HttpInputMessage beforeBodyRead(
            HttpInputMessage inputMessage,
            MethodParameter parameter,
            Type targetType,
            Class<? extends HttpMessageConverter<?>> converterType) throws IOException {
        StrictFieldBinding binding = binding(parameter);
        if (binding == null) {
            return inputMessage;
        }
        byte[] rawBytes = binder.readBounded(inputMessage.getBody(), binding.maxBytes());
        binder.validateAndAuthorize(rawBytes, targetType, binding);
        StrictSubmittedFieldBinder.markRequestVerified();
        return new BufferedHttpInputMessage(rawBytes, inputMessage.getHeaders());
    }

    @Override
    public Object afterBodyRead(
            Object body,
            HttpInputMessage inputMessage,
            MethodParameter parameter,
            Type targetType,
            Class<? extends HttpMessageConverter<?>> converterType) {
        StrictSubmittedFieldBinder.clearRequestVerified();
        return body;
    }

    @Override
    public Object handleEmptyBody(
            Object body,
            HttpInputMessage inputMessage,
            MethodParameter parameter,
            Type targetType,
            Class<? extends HttpMessageConverter<?>> converterType) {
        StrictSubmittedFieldBinder.clearRequestVerified();
        return body;
    }

    private static StrictFieldBinding binding(MethodParameter parameter) {
        StrictFieldBinding onParam = parameter.getParameterAnnotation(StrictFieldBinding.class);
        return onParam != null ? onParam : parameter.getMethodAnnotation(StrictFieldBinding.class);
    }

    private static final class BufferedHttpInputMessage implements HttpInputMessage {
        private final byte[] bytes;
        private final HttpHeaders headers;

        private BufferedHttpInputMessage(byte[] bytes, HttpHeaders headers) {
            this.bytes = bytes;
            this.headers = headers;
        }

        @Override
        public InputStream getBody() {
            return new ByteArrayInputStream(bytes);
        }

        @Override
        public HttpHeaders getHeaders() {
            return headers;
        }
    }
}
