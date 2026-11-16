package com.aegis.mcp.security.annotation;

/**
 * Logical evaluation mode for multiple scopes declared on {@link RequireMcpScope}.
 */
public enum LogicalMode {
    /**
     * All declared scopes must be present in the active {@code McpTenantContext}.
     */
    ALL,

    /**
     * At least one of the declared scopes must be present in the active {@code McpTenantContext}.
     */
    ANY
}
