package com.aegis.mcp.security.demo;

import com.aegis.mcp.security.annotation.RequireMcpScope;
import com.aegis.mcp.security.audit.InMemoryMcpAuditSink;
import com.aegis.mcp.security.audit.McpAuditEvent;
import com.aegis.mcp.security.audit.OpenTelemetryMcpAuditExporter;
import com.aegis.mcp.security.context.McpTenantContext;
import com.aegis.mcp.security.context.McpTenantContextHolder;
import com.aegis.mcp.security.context.McpTenantTaskDecorator;
import com.aegis.mcp.security.exception.McpAccessDeniedException;
import com.aegis.mcp.security.oauth2.McpJwtAssertionService;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.junit.jupiter.api.Test;
import org.slf4j.MDC;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringBootConfiguration;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Live end-to-end dry-run showcase starting an embedded Tomcat MCP server
 * and exercising all security, context propagation, and audit capabilities.
 */
@SpringBootTest(
        classes = McpSecurityLiveDryRunTest.DemoMcpServerApp.class,
        webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
        properties = {
                "mcp.security.issuer=https://auth.aegis-enterprise.io",
                "mcp.security.audience=mcp://prod-sre-cluster",
                "mcp.security.hmac-secret=enterprise-dry-run-hmac-signing-secret-2026-256bit",
                "mcp.security.clients.aegis-sre-agent.client-secret=aegis-sre-client-secret-2026",
                "mcp.security.clients.aegis-sre-agent.tenant-id=tenant-acme"
        }
)
class McpSecurityLiveDryRunTest {

    @LocalServerPort
    private int port;

    @Autowired
    private TestRestTemplate restTemplate;

    @Autowired
    private McpJwtAssertionService assertionService;

    @Autowired
    private InMemoryMcpAuditSink auditSink;

    @Autowired
    private MeterRegistry meterRegistry;

    @Test
    void executeLiveDryRunShowcase() {
        auditSink.clear();

        StringBuilder report = new StringBuilder();
        report.append("\n================================================================================\n");
        report.append(" SPRING-BOOT-STARTER-MCP-SECURITY :: LIVE DRY-RUN SHOWCASE (Tomcat port ").append(port).append(")\n");
        report.append("================================================================================\n");

        // 1. RFC 7523 Client Assertion
        String clientAssertion = assertionService.createClientAssertion(
                "aegis-sre-agent", "aegis-sre-client-secret-2026");
        String verifiedClientId = assertionService.verifyClientAssertion(clientAssertion);
        assertThat(verifiedClientId).isEqualTo("aegis-sre-agent");
        report.append("\n[1] RFC 7523 Client Assertion (jwt-bearer)\n");
        report.append("    -> Minted assertion (len=").append(clientAssertion.length())
                .append(" chars) | Verified client_id=").append(verifiedClientId).append("\n");

        // 2. Authorized Tool Execution + Java 21 Virtual Thread Propagation
        String podsToken = assertionService.issueAccessToken(
                "sre-triage-agent",
                "tenant-acme",
                "cap-k8s-diagnostics",
                Set.of("k8s:logs:read"),
                "trace-dryrun-001",
                12000,
                90
        );
        ResponseEntity<Map> podsResponse = restTemplate.exchange(
                "http://localhost:" + port + "/mcp/tools/k8s/pods",
                HttpMethod.GET,
                bearerEntity(podsToken),
                Map.class
        );
        assertThat(podsResponse.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(podsResponse.getBody()).containsEntry("tenantId", "tenant-acme");
        assertThat(podsResponse.getBody()).containsEntry("virtualThread", true);
        assertThat(podsResponse.getBody()).containsEntry("mdcTenantId", "tenant-acme");
        report.append("\n[2] Authorized Tool Call + Java 21 Virtual Thread Propagation\n");
        report.append("    -> GET /mcp/tools/k8s/pods => HTTP ").append(podsResponse.getStatusCode().value())
                .append(" | body=").append(podsResponse.getBody()).append("\n");

        // 3. Token Replay Attack Prevention (jti)
        ResponseEntity<String> replayResponse = restTemplate.exchange(
                "http://localhost:" + port + "/mcp/tools/k8s/pods",
                HttpMethod.GET,
                bearerEntity(podsToken),
                String.class
        );
        assertThat(replayResponse.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        String replayWwwAuth = replayResponse.getHeaders().getFirst(HttpHeaders.WWW_AUTHENTICATE);
        assertThat(replayWwwAuth).contains("invalid_token");
        report.append("\n[3] JTI Replay Attack Prevention\n");
        report.append("    -> Replayed GET /mcp/tools/k8s/pods => HTTP ").append(replayResponse.getStatusCode().value())
                .append(" | WWW-Authenticate: ").append(replayWwwAuth).append("\n");

        // 4. Declarative Scope Enforcement (@RequireMcpScope) -> 403 Forbidden
        String readOnlyToken = assertionService.issueAccessToken(
                "sre-observer-agent",
                "tenant-acme",
                "cap-k8s-readonly",
                Set.of("k8s:logs:read"),
                "trace-dryrun-002",
                8000,
                60
        );
        ResponseEntity<String> restartResponse = restTemplate.exchange(
                "http://localhost:" + port + "/mcp/tools/k8s/restart",
                HttpMethod.POST,
                bearerEntity(readOnlyToken),
                String.class
        );
        assertThat(restartResponse.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
        String scopeWwwAuth = restartResponse.getHeaders().getFirst(HttpHeaders.WWW_AUTHENTICATE);
        assertThat(scopeWwwAuth).contains("insufficient_scope").contains("k8s:pods:restart");
        report.append("\n[4] Declarative Scope Enforcement (@RequireMcpScope)\n");
        report.append("    -> POST /mcp/tools/k8s/restart => HTTP ").append(restartResponse.getStatusCode().value())
                .append(" | WWW-Authenticate: ").append(scopeWwwAuth).append("\n");

        // 5. RFC 8693 Scope Attenuation & Escalation Guard
        String broadToken = assertionService.issueAccessToken(
                "sre-orchestrator",
                "tenant-globex",
                "cap-multi-tool",
                Set.of("k8s:logs:read", "db:select"),
                "trace-dryrun-003",
                16000,
                120
        );
        McpTenantContext parentCtx = assertionService.verifyAndExtractContext(broadToken);
        String attenuatedToken = assertionService.exchangeForToolScopedToken(
                parentCtx,
                "mcp://prod-sre-cluster",
                Set.of("db:select"),
                60
        );
        ResponseEntity<Map> dbResponse = restTemplate.exchange(
                "http://localhost:" + port + "/mcp/tools/db/query",
                HttpMethod.GET,
                bearerEntity(attenuatedToken),
                Map.class
        );
        assertThat(dbResponse.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(dbResponse.getBody()).containsEntry("scopes", List.of("db:select"));

        assertThatThrownBy(() -> assertionService.exchangeForToolScopedToken(
                parentCtx, "mcp://prod-sre-cluster", Set.of("admin:drop"), 60))
                .isInstanceOf(McpAccessDeniedException.class);
        report.append("\n[5] RFC 8693 Scope Attenuation & Escalation Guard\n");
        report.append("    -> Attenuated [k8s:logs:read, db:select] -> [db:select] | GET /mcp/tools/db/query => HTTP ")
                .append(dbResponse.getStatusCode().value()).append(" | Escalation [admin:drop] => BLOCKED (McpAccessDeniedException)\n");

        // 6. OpenTelemetry Audit Trail & Micrometer Counters
        List<McpAuditEvent> events = auditSink.getEvents();
        assertThat(events).hasSize(7);
        report.append("\n[6] OpenTelemetry Audit Trail (").append(events.size()).append(" events captured)\n");
        for (McpAuditEvent evt : events) {
            report.append(String.format("    %-16s | %-5s | tenant=%-13s | tool=%-18s | trace=%-18s | reason=%s%n",
                    evt.eventType(), evt.outcome(), evt.tenantId(), evt.toolName(), evt.traceId(), evt.reason()));
        }

        double totalMetric = meterRegistry.find(OpenTelemetryMcpAuditExporter.METRIC_AUDIT_EVENTS)
                .counters()
                .stream()
                .mapToDouble(Counter::count)
                .sum();
        assertThat(totalMetric).isEqualTo(7.0);
        report.append("\n    Micrometer Counter '").append(OpenTelemetryMcpAuditExporter.METRIC_AUDIT_EVENTS)
                .append("' total=").append((int) totalMetric).append("\n");
        report.append("================================================================================\n");

        System.out.println(report);
    }

    private static HttpEntity<Void> bearerEntity(String token) {
        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(token);
        return new HttpEntity<>(headers);
    }

    @SpringBootConfiguration
    @EnableAutoConfiguration
    @Import(DemoMcpToolController.class)
    static class DemoMcpServerApp {

        @Bean
        MeterRegistry simpleMeterRegistry() {
            return new SimpleMeterRegistry();
        }
    }

    @RestController
    static class DemoMcpToolController {

        private final McpTenantTaskDecorator taskDecorator;

        DemoMcpToolController(McpTenantTaskDecorator taskDecorator) {
            this.taskDecorator = taskDecorator;
        }

        @GetMapping("/mcp/tools/k8s/pods")
        @RequireMcpScope(value = {"k8s:logs:read"}, toolName = "k8s.pods.logs")
        Map<String, Object> getPodLogs() throws Exception {
            AtomicReference<Map<String, Object>> resultRef = new AtomicReference<>();
            Runnable decorated = taskDecorator.decorate(() -> {
                McpTenantContext ctx = McpTenantContextHolder.require();
                Map<String, Object> payload = new LinkedHashMap<>();
                payload.put("tenantId", ctx.tenantId());
                payload.put("capabilityId", ctx.capabilityId());
                payload.put("traceId", ctx.traceId());
                payload.put("virtualThread", Thread.currentThread().isVirtual());
                payload.put("mdcTenantId", MDC.get(McpTenantContextHolder.MDC_TENANT_ID));
                payload.put("mdcTraceId", MDC.get(McpTenantContextHolder.MDC_TRACE_ID));
                resultRef.set(payload);
            });
            try (ExecutorService executor = Executors.newVirtualThreadPerTaskExecutor()) {
                executor.submit(decorated).get();
            }
            return resultRef.get();
        }

        @PostMapping("/mcp/tools/k8s/restart")
        @RequireMcpScope(value = {"k8s:pods:restart"}, toolName = "k8s.pods.restart")
        Map<String, String> restartPod() {
            return Map.of("status", "restarted");
        }

        @GetMapping("/mcp/tools/db/query")
        @RequireMcpScope(value = {"db:select"}, toolName = "db.postgres.query")
        Map<String, Object> queryDatabase() {
            McpTenantContext ctx = McpTenantContextHolder.require();
            return Map.of(
                    "tenantId", ctx.tenantId(),
                    "scopes", ctx.scopes().stream().sorted().toList(),
                    "rows", 42
            );
        }
    }
}
