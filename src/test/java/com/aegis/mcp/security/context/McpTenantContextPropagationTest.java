package com.aegis.mcp.security.context;

import com.aegis.mcp.security.config.McpSecurityProperties;
import com.aegis.mcp.security.oauth2.McpJwtAssertionService;
import com.aegis.mcp.security.oauth2.McpTokenReplayCache;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.slf4j.MDC;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpRequest;
import org.springframework.http.HttpStatus;
import org.springframework.http.client.ClientHttpRequestExecution;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.mock.http.client.MockClientHttpRequest;
import org.springframework.mock.http.client.MockClientHttpResponse;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class McpTenantContextPropagationTest {

    @AfterEach
    void cleanup() {
        McpTenantContextHolder.clear();
        MDC.clear();
    }

    @Test
    void scopesNestedContextsAndRestoresSlf4jMdc() {
        McpTenantContext outer = new McpTenantContext(
                "tenant-outer", "cap-outer", "subj-outer",
                Set.of("read"), "trace-outer", "jti-1", 4000, 30, Map.of());
        McpTenantContext inner = new McpTenantContext(
                "tenant-inner", "cap-inner", "subj-inner",
                Set.of("write"), "trace-inner", "jti-2", 8000, 60, Map.of());

        McpTenantContextHolder.runWithContext(outer, () -> {
            assertThat(McpTenantContextHolder.require().tenantId()).isEqualTo("tenant-outer");
            assertThat(MDC.get(McpTenantContextHolder.MDC_TENANT_ID)).isEqualTo("tenant-outer");
            assertThat(MDC.get(McpTenantContextHolder.MDC_TRACE_ID)).isEqualTo("trace-outer");

            String nestedResult = McpTenantContextHolder.callWithContext(inner, () -> {
                assertThat(McpTenantContextHolder.require().tenantId()).isEqualTo("tenant-inner");
                assertThat(MDC.get(McpTenantContextHolder.MDC_TENANT_ID)).isEqualTo("tenant-inner");
                assertThat(MDC.get(McpTenantContextHolder.MDC_CAPABILITY_ID)).isEqualTo("cap-inner");
                return "ok";
            });

            assertThat(nestedResult).isEqualTo("ok");
            assertThat(McpTenantContextHolder.require().tenantId()).isEqualTo("tenant-outer");
            assertThat(MDC.get(McpTenantContextHolder.MDC_TENANT_ID)).isEqualTo("tenant-outer");
        });

        assertThat(McpTenantContextHolder.get()).isEmpty();
        assertThat(MDC.get(McpTenantContextHolder.MDC_TENANT_ID)).isNull();
        assertThatThrownBy(McpTenantContextHolder::require)
                .isInstanceOf(IllegalStateException.class);
    }

    @Test
    void propagatesContextAndMdcAcrossJava21VirtualThreadsViaTaskDecorator() throws Exception {
        McpTenantContext context = new McpTenantContext(
                "tenant-vt", "cap-vt", "agent-vt",
                Set.of("k8s:read"), "trace-vt-99", "jti-vt", 5000, 50, Map.of());
        McpTenantTaskDecorator decorator = new McpTenantTaskDecorator();

        McpTenantContextHolder.set(context);
        MDC.put("custom.correlation", "corr-123");

        AtomicReference<String> observedTenant = new AtomicReference<>();
        AtomicReference<String> observedMdcTenant = new AtomicReference<>();
        AtomicReference<String> observedCustomMdc = new AtomicReference<>();
        AtomicReference<Boolean> isVirtualThread = new AtomicReference<>(false);

        Runnable decorated = decorator.decorate(() -> {
            isVirtualThread.set(Thread.currentThread().isVirtual());
            observedTenant.set(McpTenantContextHolder.require().tenantId());
            observedMdcTenant.set(MDC.get(McpTenantContextHolder.MDC_TENANT_ID));
            observedCustomMdc.set(MDC.get("custom.correlation"));
        });

        // Clear caller before submitting to a virtual thread executor to prove snapshot capture
        McpTenantContextHolder.clear();
        MDC.clear();

        try (ExecutorService executor = Executors.newVirtualThreadPerTaskExecutor()) {
            Future<?> future = executor.submit(decorated);
            future.get();
        }

        assertThat(isVirtualThread.get()).isTrue();
        assertThat(observedTenant.get()).isEqualTo("tenant-vt");
        assertThat(observedMdcTenant.get()).isEqualTo("tenant-vt");
        assertThat(observedCustomMdc.get()).isEqualTo("corr-123");
    }

    @Test
    void outboundHttpInterceptorPropagatesHeadersAndAttenuatedToken() throws Exception {
        McpSecurityProperties props = new McpSecurityProperties();
        props.setHmacSecret("test-interceptor-hmac-secret-1234567890");
        McpJwtAssertionService assertionService = new McpJwtAssertionService(props, new McpTokenReplayCache());

        McpTenantContext ctx = new McpTenantContext(
                "tenant-http", "cap-http", "agent-http",
                Set.of("k8s:logs:read", "k8s:pods:delete"), "trace-http-1", "jti-parent", 8000, 60, Map.of());

        McpTenantClientHttpRequestInterceptor interceptor = new McpTenantClientHttpRequestInterceptor(
                assertionService,
                true,
                "mcp://downstream-tool",
                Set.of("k8s:logs:read"),
                45
        );

        MockClientHttpRequest request = new MockClientHttpRequest(
                HttpMethod.POST, URI.create("https://mcp.internal/tools/logs"));
        AtomicReference<HttpHeaders> capturedHeaders = new AtomicReference<>();

        ClientHttpRequestExecution execution = (HttpRequest req, byte[] body) -> {
            capturedHeaders.set(req.getHeaders());
            return new MockClientHttpResponse("{}".getBytes(StandardCharsets.UTF_8), HttpStatus.OK);
        };

        McpTenantContextHolder.runWithContext(ctx, () -> {
            try (ClientHttpResponse ignored = interceptor.intercept(request, new byte[0], execution)) {
                // executed
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        });

        HttpHeaders headers = capturedHeaders.get();
        assertThat(headers.getFirst(McpTenantClientHttpRequestInterceptor.HEADER_TENANT_ID)).isEqualTo("tenant-http");
        assertThat(headers.getFirst(McpTenantClientHttpRequestInterceptor.HEADER_CAPABILITY_ID)).isEqualTo("cap-http");
        assertThat(headers.getFirst(McpTenantClientHttpRequestInterceptor.HEADER_TRACE_ID)).isEqualTo("trace-http-1");
        assertThat(headers.getFirst(HttpHeaders.AUTHORIZATION)).startsWith("Bearer ");
    }
}
