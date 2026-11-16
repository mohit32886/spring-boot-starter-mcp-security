package com.aegis.mcp.security.autoconfigure;

import com.aegis.mcp.security.annotation.McpScopeEnforcementAspect;
import com.aegis.mcp.security.annotation.RequireMcpScope;
import com.aegis.mcp.security.audit.InMemoryMcpAuditSink;
import com.aegis.mcp.security.audit.McpAuditEvent;
import com.aegis.mcp.security.audit.McpAuditTrailService;
import com.aegis.mcp.security.audit.OpenTelemetryMcpAuditExporter;
import com.aegis.mcp.security.context.McpTenantClientHttpRequestInterceptor;
import com.aegis.mcp.security.context.McpTenantContext;
import com.aegis.mcp.security.context.McpTenantContextHolder;
import com.aegis.mcp.security.context.McpTenantTaskDecorator;
import com.aegis.mcp.security.filter.McpJwtAuthenticationFilter;
import com.aegis.mcp.security.oauth2.McpJwtAssertionService;
import com.aegis.mcp.security.oauth2.McpTokenReplayCache;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringBootConfiguration;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.autoconfigure.aop.AopAutoConfiguration;
import org.springframework.boot.autoconfigure.security.servlet.SecurityAutoConfiguration;
import org.springframework.boot.autoconfigure.web.servlet.WebMvcAutoConfiguration;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.runner.WebApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.http.HttpHeaders;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

class McpSecurityAutoConfigurationIntegrationTest {

    @Nested
    class ContextRunnerTests {

        private final WebApplicationContextRunner contextRunner = new WebApplicationContextRunner()
                .withConfiguration(org.springframework.boot.autoconfigure.AutoConfigurations.of(
                        SecurityAutoConfiguration.class,
                        WebMvcAutoConfiguration.class,
                        AopAutoConfiguration.class,
                        McpSecurityAutoConfiguration.class
                ));

        @Test
        void registersAllStarterBeansByDefault() {
            contextRunner.run(context -> {
                assertThat(context).hasSingleBean(McpTokenReplayCache.class);
                assertThat(context).hasSingleBean(McpJwtAssertionService.class);
                assertThat(context).hasSingleBean(OpenTelemetryMcpAuditExporter.class);
                assertThat(context).hasSingleBean(InMemoryMcpAuditSink.class);
                assertThat(context).hasSingleBean(McpAuditTrailService.class);
                assertThat(context).hasSingleBean(McpScopeEnforcementAspect.class);
                assertThat(context).hasSingleBean(McpTenantTaskDecorator.class);
                assertThat(context).hasSingleBean(McpTenantClientHttpRequestInterceptor.class);
                assertThat(context).hasSingleBean(McpJwtAuthenticationFilter.class);
                assertThat(context).hasBean("mcpSecurityFilterChain");
            });
        }

        @Test
        void backsOffWhenDisabledViaProperty() {
            contextRunner
                    .withPropertyValues("mcp.security.enabled=false")
                    .run(context -> {
                        assertThat(context).doesNotHaveBean(McpJwtAssertionService.class);
                        assertThat(context).doesNotHaveBean(McpJwtAuthenticationFilter.class);
                        assertThat(context).doesNotHaveBean("mcpSecurityFilterChain");
                    });
        }

        @Test
        void respectsCustomBeanOverrides() {
            contextRunner
                    .withUserConfiguration(CustomReplayCacheConfig.class)
                    .run(context -> {
                        assertThat(context).hasSingleBean(McpTokenReplayCache.class);
                        assertThat(context.getBean(McpTokenReplayCache.class))
                                .isSameAs(CustomReplayCacheConfig.CUSTOM_CACHE);
                    });
        }

        static class CustomReplayCacheConfig {
            static final McpTokenReplayCache CUSTOM_CACHE = new McpTokenReplayCache(50);

            @Bean
            McpTokenReplayCache customReplayCache() {
                return CUSTOM_CACHE;
            }
        }
    }

    @Nested
    @SpringBootTest(
            classes = SampleMcpServerApplication.class,
            properties = {
                    "mcp.security.issuer=https://auth.integration.test",
                    "mcp.security.audience=mcp://integration-cluster",
                    "mcp.security.hmac-secret=integration-test-hmac-secret-at-least-32-bytes"
            }
    )
    @AutoConfigureMockMvc
    class EndToEndWebSecurityTests {

        @Autowired
        private MockMvc mockMvc;

        @Autowired
        private McpJwtAssertionService assertionService;

        @Autowired
        private InMemoryMcpAuditSink auditSink;

        @BeforeEach
        void resetSink() {
            auditSink.clear();
        }

        @Test
        void leavesNonProtectedPathsAccessible() throws Exception {
            mockMvc.perform(get("/public/health"))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.status").value("UP"));

            assertThat(auditSink.getEvents()).isEmpty();
        }

        @Test
        void returns401OnMissingAndInvalidBearerTokens() throws Exception {
            mockMvc.perform(get("/mcp/tools/pods"))
                    .andExpect(status().isUnauthorized())
                    .andExpect(header().string(HttpHeaders.WWW_AUTHENTICATE,
                            org.hamcrest.Matchers.containsString("invalid_request")))
                    .andExpect(jsonPath("$.error").value("invalid_request"));

            mockMvc.perform(get("/mcp/tools/pods")
                            .header(HttpHeaders.AUTHORIZATION, "Bearer tampered.invalid.jwt"))
                    .andExpect(status().isUnauthorized())
                    .andExpect(header().string(HttpHeaders.WWW_AUTHENTICATE,
                            org.hamcrest.Matchers.containsString("invalid_token")))
                    .andExpect(jsonPath("$.error").value("invalid_token"));

            assertThat(auditSink.getEvents())
                    .extracting(McpAuditEvent::outcome)
                    .containsExactly(McpAuditEvent.Outcome.DENY, McpAuditEvent.Outcome.DENY);
        }

        @Test
        void returns403WhenScopeIsInsufficientAndAuditsDenial() throws Exception {
            String readOnlyToken = assertionService.issueAccessToken(
                    "agent-observer",
                    "tenant-acme",
                    "cap-k8s-readonly",
                    Set.of("k8s:logs:read"),
                    "trace-403-check",
                    4000,
                    60
            );

            mockMvc.perform(post("/mcp/tools/restart")
                            .header(HttpHeaders.AUTHORIZATION, "Bearer " + readOnlyToken))
                    .andExpect(status().isForbidden())
                    .andExpect(header().string(HttpHeaders.WWW_AUTHENTICATE,
                            org.hamcrest.Matchers.containsString("insufficient_scope")))
                    .andExpect(jsonPath("$.error").value("insufficient_scope"));

            assertThat(auditSink.getEvents()).hasSize(2);
            assertThat(auditSink.getEvents().get(0).eventType()).isEqualTo(McpAuditEvent.EventType.AUTHENTICATION);
            assertThat(auditSink.getEvents().get(0).outcome()).isEqualTo(McpAuditEvent.Outcome.ALLOW);
            assertThat(auditSink.getEvents().get(1).eventType()).isEqualTo(McpAuditEvent.EventType.TOOL_INVOCATION);
            assertThat(auditSink.getEvents().get(1).outcome()).isEqualTo(McpAuditEvent.Outcome.DENY);
        }

        @Test
        void executesAuthorizedToolPropagatesTenantContextAndBlocksReplay() throws Exception {
            String validToken = assertionService.issueAccessToken(
                    "agent-sre",
                    "tenant-globex",
                    "cap-pod-diagnostics",
                    Set.of("k8s:logs:read"),
                    "trace-200-check",
                    10000,
                    90
            );

            mockMvc.perform(get("/mcp/tools/pods")
                            .header(HttpHeaders.AUTHORIZATION, "Bearer " + validToken))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.tenantId").value("tenant-globex"))
                    .andExpect(jsonPath("$.capabilityId").value("cap-pod-diagnostics"))
                    .andExpect(jsonPath("$.traceId").value("trace-200-check"));

            // Context must be cleared after request completes
            assertThat(McpTenantContextHolder.get()).isEmpty();

            assertThat(auditSink.getEvents()).hasSize(2);
            assertThat(auditSink.getEvents())
                    .extracting(McpAuditEvent::outcome)
                    .containsExactly(McpAuditEvent.Outcome.ALLOW, McpAuditEvent.Outcome.ALLOW);

            // Replaying the exact same JWT must be rejected with 401
            mockMvc.perform(get("/mcp/tools/pods")
                            .header(HttpHeaders.AUTHORIZATION, "Bearer " + validToken))
                    .andExpect(status().isUnauthorized())
                    .andExpect(jsonPath("$.error").value("invalid_token"));
        }
    }

    @SpringBootConfiguration
    @EnableAutoConfiguration
    @Import(SampleMcpToolController.class)
    static class SampleMcpServerApplication {
    }

    @RestController
    static class SampleMcpToolController {

        @GetMapping("/public/health")
        Map<String, String> health() {
            return Map.of("status", "UP");
        }

        @GetMapping("/mcp/tools/pods")
        @RequireMcpScope(value = {"k8s:logs:read"}, toolName = "k8s.pods.logs")
        Map<String, String> readPods() {
            McpTenantContext ctx = McpTenantContextHolder.require();
            return Map.of(
                    "tenantId", ctx.tenantId(),
                    "capabilityId", ctx.capabilityId(),
                    "traceId", ctx.traceId()
            );
        }

        @PostMapping("/mcp/tools/restart")
        @RequireMcpScope(value = {"k8s:pods:restart"}, toolName = "k8s.pods.restart")
        Map<String, String> restartPod() {
            return Map.of("restarted", "true");
        }
    }
}
