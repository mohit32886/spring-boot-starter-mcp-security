package com.aegis.mcp.security.audit;

import java.util.List;
import java.util.concurrent.ConcurrentLinkedDeque;

/**
 * Bounded, thread-safe ring buffer storing recent {@link McpAuditEvent} instances
 * for diagnostics, actuator reporting, and integration testing.
 */
public class InMemoryMcpAuditSink implements McpAuditExporter {

    private static final int DEFAULT_MAX_EVENTS = 1_000;

    private final ConcurrentLinkedDeque<McpAuditEvent> events = new ConcurrentLinkedDeque<>();
    private final int maxEvents;

    public InMemoryMcpAuditSink() {
        this(DEFAULT_MAX_EVENTS);
    }

    public InMemoryMcpAuditSink(int maxEvents) {
        if (maxEvents <= 0) {
            throw new IllegalArgumentException("maxEvents must be positive");
        }
        this.maxEvents = maxEvents;
    }

    @Override
    public void export(McpAuditEvent event) {
        if (event == null) {
            return;
        }
        events.addLast(event);
        while (events.size() > maxEvents) {
            events.pollFirst();
        }
    }

    public List<McpAuditEvent> getEvents() {
        return List.copyOf(events);
    }

    public List<McpAuditEvent> getEventsForTenant(String tenantId) {
        if (tenantId == null || tenantId.isBlank()) {
            return List.of();
        }
        return events.stream()
                .filter(e -> tenantId.equals(e.tenantId()))
                .toList();
    }

    public int size() {
        return events.size();
    }

    public void clear() {
        events.clear();
    }
}
