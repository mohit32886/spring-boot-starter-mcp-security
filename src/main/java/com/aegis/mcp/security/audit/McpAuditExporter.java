package com.aegis.mcp.security.audit;

/**
 * Service Provider Interface (SPI) for exporting MCP security audit events
 * to observability backends, SIEM pipelines, or in-memory sinks.
 */
@FunctionalInterface
public interface McpAuditExporter {

    void export(McpAuditEvent event);
}
