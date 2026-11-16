package com.aegis.mcp.security.exception;

import org.springframework.security.access.AccessDeniedException;

import java.util.Set;

/**
 * Thrown when an authenticated MCP principal lacks the required OAuth 2.0 scope,
 * capability attribution, or attempts scope escalation during token attenuation.
 * Extends Spring Security's {@link AccessDeniedException} (a {@link RuntimeException})
 * so servlet exception translation automatically produces HTTP 403 responses.
 */
public class McpAccessDeniedException extends AccessDeniedException {

    private final Set<String> requiredScopes;
    private final Set<String> grantedScopes;

    public McpAccessDeniedException(String message) {
        this(message, Set.of(), Set.of());
    }

    public McpAccessDeniedException(String message, Set<String> requiredScopes, Set<String> grantedScopes) {
        super(message);
        this.requiredScopes = requiredScopes == null ? Set.of() : Set.copyOf(requiredScopes);
        this.grantedScopes = grantedScopes == null ? Set.of() : Set.copyOf(grantedScopes);
    }

    public Set<String> getRequiredScopes() {
        return requiredScopes;
    }

    public Set<String> getGrantedScopes() {
        return grantedScopes;
    }
}
