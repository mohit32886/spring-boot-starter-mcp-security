package com.aegis.mcp.security.annotation;

import com.aegis.mcp.security.audit.InMemoryMcpAuditSink;
import com.aegis.mcp.security.audit.McpAuditEvent;
import com.aegis.mcp.security.audit.McpAuditTrailService;
import com.aegis.mcp.security.context.McpTenantContext;
import com.aegis.mcp.security.context.McpTenantContextHolder;
import com.aegis.mcp.security.exception.McpAccessDeniedException;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.aop.aspectj.annotation.AspectJProxyFactory;

import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class McpScopeEnforcementAspectTest {

    private InMemoryMcpAuditSink auditSink;
    private SampleMcpTool proxyTool;

    @BeforeEach
    void setUp() {
        auditSink = new InMemoryMcpAuditSink();
        McpAuditTrailService auditService = new McpAuditTrailService(List.of(auditSink));
        McpScopeEnforcementAspect aspect = new McpScopeEnforcementAspect(auditService);

        AspectJProxyFactory factory = new AspectJProxyFactory(new SampleMcpTool());
        factory.addAspect(aspect);
        proxyTool = factory.getProxy();
    }

    @AfterEach
    void tearDown() {
        McpTenantContextHolder.clear();
    }

    @Test
    void allowsExecutionWhenAllRequiredScopesPresentAndAuditsEvent() {
        McpTenantContext ctx = new McpTenantContext(
                "tenant-fin", "cap-ledger", "agent-fin",
                Set.of("ledger:read", "audit:view"), "trace-1", "jti-1", 4000, 60, Map.of());

        String result = McpTenantContextHolder.callWithContext(ctx, () -> proxyTool.readAll());

        assertThat(result).isEqualTo("ledger-ok");
        assertThat(auditSink.getEvents()).hasSize(1);
        McpAuditEvent event = auditSink.getEvents().getFirst();
        assertThat(event.eventType()).isEqualTo(McpAuditEvent.EventType.TOOL_INVOCATION);
        assertThat(event.outcome()).isEqualTo(McpAuditEvent.Outcome.ALLOW);
        assertThat(event.toolName()).isEqualTo("ledger.readAll");
        assertThat(event.tenantId()).isEqualTo("tenant-fin");
    }

    @Test
    void enforcesAnyLogicalModeAndRejectsMissingScope() {
        McpTenantContext allowedCtx = new McpTenantContext(
                "tenant-ops", "cap-ops", "agent-ops",
                Set.of("ops:restart"), "trace-2", "jti-2", 4000, 60, Map.of());

        String out = McpTenantContextHolder.callWithContext(allowedCtx, () -> proxyTool.anyOps());
        assertThat(out).isEqualTo("ops-ok");

        McpTenantContext deniedCtx = new McpTenantContext(
                "tenant-ops", "cap-ops", "agent-ops",
                Set.of("ops:restart"), "trace-3", "jti-3", 4000, 60, Map.of());

        assertThatThrownBy(() -> McpTenantContextHolder.callWithContext(deniedCtx, () -> proxyTool.readAll()))
                .isInstanceOf(McpAccessDeniedException.class)
                .hasMessageContaining("ledger.readAll");

        assertThat(auditSink.getEvents()).hasSize(2);
        McpAuditEvent denyEvent = auditSink.getEvents().get(1);
        assertThat(denyEvent.outcome()).isEqualTo(McpAuditEvent.Outcome.DENY);
        assertThat(denyEvent.requiredScopes()).containsExactlyInAnyOrder("ledger:read", "audit:view");
    }

    @Test
    void rejectsMissingCapabilityWhenRequireCapabilityIsTrue() {
        McpTenantContext noCapCtx = new McpTenantContext(
                "tenant-ops", "", "agent-ops",
                Set.of("ledger:read", "audit:view"), "trace-4", "jti-4", 4000, 60, Map.of());

        assertThatThrownBy(() -> McpTenantContextHolder.callWithContext(noCapCtx, () -> proxyTool.readAll()))
                .isInstanceOf(McpAccessDeniedException.class)
                .hasMessageContaining("capability_id");

        String optionalCapOut = McpTenantContextHolder.callWithContext(noCapCtx, () -> proxyTool.noCapabilityRequired());
        assertThat(optionalCapOut).isEqualTo("no-cap-ok");
    }

    @Test
    void rejectsInvocationWithoutTenantContext() {
        assertThatThrownBy(() -> proxyTool.readAll())
                .isInstanceOf(McpAccessDeniedException.class)
                .hasMessageContaining("McpTenantContext");

        assertThat(auditSink.getEvents()).hasSize(1);
        assertThat(auditSink.getEvents().getFirst().outcome()).isEqualTo(McpAuditEvent.Outcome.DENY);
    }

    @RequireMcpScope(value = {"default:class:scope"})
    static class SampleMcpTool {

        @RequireMcpScope(value = {"ledger:read", "audit:view"}, toolName = "ledger.readAll")
        public String readAll() {
            return "ledger-ok";
        }

        @RequireMcpScope(value = {"ops:restart", "ops:admin"}, mode = LogicalMode.ANY)
        public String anyOps() {
            return "ops-ok";
        }

        @RequireMcpScope(value = {"ledger:read"}, requireCapability = false)
        public String noCapabilityRequired() {
            return "no-cap-ok";
        }
    }
}
