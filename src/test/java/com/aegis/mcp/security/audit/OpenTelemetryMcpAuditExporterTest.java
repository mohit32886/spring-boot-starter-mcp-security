package com.aegis.mcp.security.audit;

import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import io.opentelemetry.api.trace.Span;
import io.opentelemetry.api.trace.StatusCode;
import io.opentelemetry.api.trace.Tracer;
import io.opentelemetry.context.Scope;
import io.opentelemetry.sdk.testing.exporter.InMemorySpanExporter;
import io.opentelemetry.sdk.trace.SdkTracerProvider;
import io.opentelemetry.sdk.trace.data.EventData;
import io.opentelemetry.sdk.trace.data.SpanData;
import io.opentelemetry.sdk.trace.export.SimpleSpanProcessor;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

class OpenTelemetryMcpAuditExporterTest {

    private InMemorySpanExporter spanExporter;
    private SdkTracerProvider tracerProvider;
    private Tracer tracer;
    private SimpleMeterRegistry meterRegistry;
    private OpenTelemetryMcpAuditExporter auditExporter;

    @BeforeEach
    void setUp() {
        spanExporter = InMemorySpanExporter.create();
        tracerProvider = SdkTracerProvider.builder()
                .addSpanProcessor(SimpleSpanProcessor.create(spanExporter))
                .build();
        tracer = tracerProvider.get("com.aegis.mcp.security.test");
        meterRegistry = new SimpleMeterRegistry();
        auditExporter = new OpenTelemetryMcpAuditExporter(meterRegistry);
    }

    @AfterEach
    void tearDown() {
        tracerProvider.close();
        meterRegistry.close();
    }

    @Test
    void exportsAllowEventAsSpanAttributesEventAndMicrometerMetric() {
        Span span = tracer.spanBuilder("mcp.tool.invoke").startSpan();
        try (Scope ignored = span.makeCurrent()) {
            McpAuditEvent event = new McpAuditEvent(
                    "evt-100",
                    Instant.now(),
                    McpAuditEvent.EventType.TOOL_INVOCATION,
                    McpAuditEvent.Outcome.ALLOW,
                    "tenant-alpha",
                    "cap-k8s-reader",
                    "agent-sre-01",
                    "k8s.getPodLogs",
                    Set.of("k8s:logs:read"),
                    Set.of("k8s:logs:read", "metrics:query"),
                    span.getSpanContext().getTraceId(),
                    span.getSpanContext().getSpanId(),
                    "jti-999",
                    "/mcp/tools/pods",
                    "Tool authorization granted",
                    14L
            );
            auditExporter.export(event);
        } finally {
            span.end();
        }

        List<SpanData> spans = spanExporter.getFinishedSpanItems();
        assertThat(spans).hasSize(1);
        SpanData finished = spans.getFirst();

        assertThat(finished.getAttributes().get(OpenTelemetryMcpAuditExporter.ATTR_TENANT_ID))
                .isEqualTo("tenant-alpha");
        assertThat(finished.getAttributes().get(OpenTelemetryMcpAuditExporter.ATTR_CAPABILITY_ID))
                .isEqualTo("cap-k8s-reader");
        assertThat(finished.getAttributes().get(OpenTelemetryMcpAuditExporter.ATTR_AUTH_SUBJECT))
                .isEqualTo("agent-sre-01");
        assertThat(finished.getAttributes().get(OpenTelemetryMcpAuditExporter.ATTR_TOOL_NAME))
                .isEqualTo("k8s.getPodLogs");
        assertThat(finished.getAttributes().get(OpenTelemetryMcpAuditExporter.ATTR_OUTCOME))
                .isEqualTo("ALLOW");
        assertThat(finished.getAttributes().get(OpenTelemetryMcpAuditExporter.ATTR_TOKEN_JTI))
                .isEqualTo("jti-999");

        assertThat(finished.getEvents()).hasSize(1);
        EventData eventData = finished.getEvents().getFirst();
        assertThat(eventData.getName()).isEqualTo(OpenTelemetryMcpAuditExporter.SPAN_EVENT_NAME);

        double count = meterRegistry.get(OpenTelemetryMcpAuditExporter.METRIC_AUDIT_EVENTS)
                .tag("event_type", "TOOL_INVOCATION")
                .tag("outcome", "ALLOW")
                .tag("tenant_id", "tenant-alpha")
                .counter()
                .count();
        assertThat(count).isEqualTo(1.0);
    }

    @Test
    void marksSpanStatusErrorOnDenyOutcome() {
        Span span = tracer.spanBuilder("mcp.tool.invoke.denied").startSpan();
        try (Scope ignored = span.makeCurrent()) {
            McpAuditEvent denyEvent = new McpAuditEvent(
                    "evt-101",
                    Instant.now(),
                    McpAuditEvent.EventType.TOOL_INVOCATION,
                    McpAuditEvent.Outcome.DENY,
                    "tenant-beta",
                    "cap-db-writer",
                    "agent-rogue",
                    "db.dropTable",
                    Set.of("db:admin"),
                    Set.of("db:read"),
                    span.getSpanContext().getTraceId(),
                    span.getSpanContext().getSpanId(),
                    "jti-111",
                    "/mcp/tools/db",
                    "Insufficient MCP scopes",
                    2L
            );
            auditExporter.export(denyEvent);
        } finally {
            span.end();
        }

        SpanData finished = spanExporter.getFinishedSpanItems().getFirst();
        assertThat(finished.getStatus().getStatusCode()).isEqualTo(StatusCode.ERROR);
        assertThat(finished.getStatus().getDescription()).isEqualTo("Insufficient MCP scopes");

        double denyCount = meterRegistry.get(OpenTelemetryMcpAuditExporter.METRIC_AUDIT_EVENTS)
                .tag("outcome", "DENY")
                .tag("tenant_id", "tenant-beta")
                .counter()
                .count();
        assertThat(denyCount).isEqualTo(1.0);
    }
}
