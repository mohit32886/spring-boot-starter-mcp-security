package com.aegis.mcp.security.audit;

import com.aegis.mcp.security.context.McpTenantContext;
import io.opentelemetry.api.trace.Span;
import io.opentelemetry.api.trace.SpanContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Instant;
import java.util.List;
import java.util.Set;
import java.util.UUID;

/**
 * Central coordinator that builds {@link McpAuditEvent} records with OpenTelemetry
 * trace/span correlation and fans them out to all registered {@link McpAuditExporter} beans.
 */
public class McpAuditTrailService {

    private static final Logger log = LoggerFactory.getLogger(McpAuditTrailService.class);

    private final List<McpAuditExporter> exporters;

    public McpAuditTrailService(List<McpAuditExporter> exporters) {
        this.exporters = exporters == null ? List.of() : List.copyOf(exporters);
    }

    public McpAuditEvent recordAuthenticationAllow(McpTenantContext context, String requestUri, long latencyMs) {
        return record(
                McpAuditEvent.EventType.AUTHENTICATION,
                McpAuditEvent.Outcome.ALLOW,
                context,
                null,
                Set.of(),
                requestUri,
                "JWT assertion verified",
                latencyMs
        );
    }

    public McpAuditEvent recordAuthenticationDeny(String requestUri, String reason, long latencyMs) {
        return record(
                McpAuditEvent.EventType.AUTHENTICATION,
                McpAuditEvent.Outcome.DENY,
                null,
                null,
                Set.of(),
                requestUri,
                reason,
                latencyMs
        );
    }

    public McpAuditEvent recordToolInvocationAllow(
            McpTenantContext context,
            String toolName,
            Set<String> requiredScopes,
            long latencyMs
    ) {
        return record(
                McpAuditEvent.EventType.TOOL_INVOCATION,
                McpAuditEvent.Outcome.ALLOW,
                context,
                toolName,
                requiredScopes,
                null,
                "Tool authorization granted",
                latencyMs
        );
    }

    public McpAuditEvent recordToolInvocationDeny(
            McpTenantContext context,
            String toolName,
            Set<String> requiredScopes,
            String reason,
            long latencyMs
    ) {
        return record(
                McpAuditEvent.EventType.TOOL_INVOCATION,
                McpAuditEvent.Outcome.DENY,
                context,
                toolName,
                requiredScopes,
                null,
                reason,
                latencyMs
        );
    }

    public McpAuditEvent record(
            McpAuditEvent.EventType eventType,
            McpAuditEvent.Outcome outcome,
            McpTenantContext context,
            String toolName,
            Set<String> requiredScopes,
            String requestUri,
            String reason,
            long latencyMs
    ) {
        SpanContext spanContext = Span.current().getSpanContext();
        String spanId = spanContext.isValid() ? spanContext.getSpanId() : null;
        String traceId = (context != null && context.traceId() != null && !context.traceId().isBlank())
                ? context.traceId()
                : (spanContext.isValid() ? spanContext.getTraceId() : null);

        McpAuditEvent event = new McpAuditEvent(
                UUID.randomUUID().toString(),
                Instant.now(),
                eventType,
                outcome,
                context != null ? context.tenantId() : null,
                context != null ? context.capabilityId() : null,
                context != null ? context.subject() : null,
                toolName,
                requiredScopes,
                context != null ? context.scopes() : Set.of(),
                traceId,
                spanId,
                context != null ? context.tokenId() : null,
                requestUri,
                reason,
                latencyMs
        );

        for (McpAuditExporter exporter : exporters) {
            try {
                exporter.export(event);
            } catch (Exception ex) {
                log.error("Failed to export MCP audit event {} via {}",
                        event.eventId(), exporter.getClass().getSimpleName(), ex);
            }
        }
        return event;
    }
}
