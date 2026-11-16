package com.aegis.mcp.security.audit;

import java.time.Instant;
import java.util.Set;

/**
 * Immutable security audit record capturing MCP authentication, client assertion,
 * token exchange, and tool invocation authorization decisions.
 */
public record McpAuditEvent(
        String eventId,
        Instant timestamp,
        EventType eventType,
        Outcome outcome,
        String tenantId,
        String capabilityId,
        String subject,
        String toolName,
        Set<String> requiredScopes,
        Set<String> grantedScopes,
        String traceId,
        String spanId,
        String tokenId,
        String requestUri,
        String reason,
        long latencyMs
) {

    public McpAuditEvent {
        requiredScopes = requiredScopes == null ? Set.of() : Set.copyOf(requiredScopes);
        grantedScopes = grantedScopes == null ? Set.of() : Set.copyOf(grantedScopes);
    }

    public enum EventType {
        AUTHENTICATION,
        CLIENT_ASSERTION,
        TOOL_INVOCATION,
        TOKEN_EXCHANGE
    }

    public enum Outcome {
        ALLOW,
        DENY
    }
}
