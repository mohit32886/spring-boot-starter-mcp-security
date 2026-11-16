package com.aegis.mcp.security.audit;

import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import io.opentelemetry.api.common.AttributeKey;
import io.opentelemetry.api.common.Attributes;
import io.opentelemetry.api.common.AttributesBuilder;
import io.opentelemetry.api.trace.Span;
import io.opentelemetry.api.trace.StatusCode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Set;

/**
 * Exports {@link McpAuditEvent} records as OpenTelemetry span attributes and structured span events
 * ({@code mcp.security.audit}), increments Micrometer audit counters, and emits structured audit logs.
 */
public class OpenTelemetryMcpAuditExporter implements McpAuditExporter {

    public static final String SPAN_EVENT_NAME = "mcp.security.audit";
    public static final String METRIC_AUDIT_EVENTS = "mcp.security.audit.events.total";

    public static final AttributeKey<String> ATTR_TENANT_ID = AttributeKey.stringKey("mcp.tenant.id");
    public static final AttributeKey<String> ATTR_CAPABILITY_ID = AttributeKey.stringKey("mcp.capability.id");
    public static final AttributeKey<String> ATTR_AUTH_SUBJECT = AttributeKey.stringKey("mcp.auth.subject");
    public static final AttributeKey<String> ATTR_TOOL_NAME = AttributeKey.stringKey("mcp.tool.name");
    public static final AttributeKey<String> ATTR_OUTCOME = AttributeKey.stringKey("mcp.security.outcome");
    public static final AttributeKey<String> ATTR_TOKEN_JTI = AttributeKey.stringKey("mcp.token.jti");

    private static final Logger log = LoggerFactory.getLogger(OpenTelemetryMcpAuditExporter.class);

    private final MeterRegistry meterRegistry;

    public OpenTelemetryMcpAuditExporter() {
        this(null);
    }

    public OpenTelemetryMcpAuditExporter(MeterRegistry meterRegistry) {
        this.meterRegistry = meterRegistry;
    }

    @Override
    public void export(McpAuditEvent event) {
        if (event == null) {
            return;
        }

        Span span = Span.current();
        setSpanAttributeIfPresent(span, ATTR_TENANT_ID, event.tenantId());
        setSpanAttributeIfPresent(span, ATTR_CAPABILITY_ID, event.capabilityId());
        setSpanAttributeIfPresent(span, ATTR_AUTH_SUBJECT, event.subject());
        setSpanAttributeIfPresent(span, ATTR_TOOL_NAME, event.toolName());
        setSpanAttributeIfPresent(span, ATTR_OUTCOME, event.outcome() != null ? event.outcome().name() : null);
        setSpanAttributeIfPresent(span, ATTR_TOKEN_JTI, event.tokenId());

        Attributes eventAttributes = buildEventAttributes(event);
        span.addEvent(SPAN_EVENT_NAME, eventAttributes, event.timestamp());

        if (event.outcome() == McpAuditEvent.Outcome.DENY) {
            span.setStatus(StatusCode.ERROR, nonBlankOrFallback(event.reason(), "MCP security policy denied"));
        }

        if (meterRegistry != null) {
            Counter.builder(METRIC_AUDIT_EVENTS)
                    .description("Total MCP security audit events by event type, outcome, and tenant")
                    .tag("event_type", event.eventType() != null ? event.eventType().name() : "UNKNOWN")
                    .tag("outcome", event.outcome() != null ? event.outcome().name() : "UNKNOWN")
                    .tag("tenant_id", nonBlankOrFallback(event.tenantId(), "unknown"))
                    .register(meterRegistry)
                    .increment();
        }

        if (event.outcome() == McpAuditEvent.Outcome.DENY) {
            log.warn("MCP_AUDIT outcome=DENY type={} tenant={} capability={} subject={} tool={} traceId={} reason={}",
                    event.eventType(), event.tenantId(), event.capabilityId(),
                    event.subject(), event.toolName(), event.traceId(), event.reason());
        } else {
            log.info("MCP_AUDIT outcome=ALLOW type={} tenant={} capability={} subject={} tool={} traceId={} latencyMs={}",
                    event.eventType(), event.tenantId(), event.capabilityId(),
                    event.subject(), event.toolName(), event.traceId(), event.latencyMs());
        }
    }

    private static Attributes buildEventAttributes(McpAuditEvent event) {
        AttributesBuilder builder = Attributes.builder()
                .put("mcp.audit.event_id", nonBlankOrFallback(event.eventId(), ""))
                .put("mcp.audit.type", event.eventType() != null ? event.eventType().name() : "UNKNOWN")
                .put("mcp.security.outcome", event.outcome() != null ? event.outcome().name() : "UNKNOWN")
                .put("mcp.latency_ms", event.latencyMs());

        putIfNonBlank(builder, "mcp.tenant.id", event.tenantId());
        putIfNonBlank(builder, "mcp.capability.id", event.capabilityId());
        putIfNonBlank(builder, "mcp.auth.subject", event.subject());
        putIfNonBlank(builder, "mcp.tool.name", event.toolName());
        putIfNonBlank(builder, "mcp.token.jti", event.tokenId());
        putIfNonBlank(builder, "mcp.trace.id", event.traceId());
        putIfNonBlank(builder, "mcp.request.uri", event.requestUri());
        putIfNonBlank(builder, "mcp.security.reason", event.reason());
        putScopesIfNonEmpty(builder, "mcp.security.required_scopes", event.requiredScopes());
        putScopesIfNonEmpty(builder, "mcp.security.granted_scopes", event.grantedScopes());
        return builder.build();
    }

    private static void setSpanAttributeIfPresent(Span span, AttributeKey<String> key, String value) {
        if (value != null && !value.isBlank()) {
            span.setAttribute(key, value);
        }
    }

    private static void putIfNonBlank(AttributesBuilder builder, String key, String value) {
        if (value != null && !value.isBlank()) {
            builder.put(key, value);
        }
    }

    private static void putScopesIfNonEmpty(AttributesBuilder builder, String key, Set<String> scopes) {
        if (scopes != null && !scopes.isEmpty()) {
            builder.put(key, String.join(" ", scopes));
        }
    }

    private static String nonBlankOrFallback(String value, String fallback) {
        return (value == null || value.isBlank()) ? fallback : value;
    }
}
