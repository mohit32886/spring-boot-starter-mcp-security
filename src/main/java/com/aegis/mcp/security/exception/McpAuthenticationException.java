package com.aegis.mcp.security.exception;

/**
 * Thrown when an incoming MCP OAuth 2.0 JWT assertion or access token fails
 * cryptographic signature verification, claim validation, expiration, or replay checks.
 */
public class McpAuthenticationException extends RuntimeException {

    public McpAuthenticationException(String message) {
        super(message);
    }

    public McpAuthenticationException(String message, Throwable cause) {
        super(message, cause);
    }
}
