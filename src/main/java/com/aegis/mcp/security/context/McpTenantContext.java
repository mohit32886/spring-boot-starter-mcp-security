package com.aegis.mcp.security.context;

import java.util.Collection;
import java.util.Map;
import java.util.Set;

/**
 * Immutable execution context carrying tenant identity, capability attribution,
 * OAuth 2.0 scopes, distributed trace ID, token ID (jti), compute budget limits,
 * and extensible metadata attributes across threads and downstream MCP calls.
 */
public record McpTenantContext(
        String tenantId,
        String capabilityId,
        String subject,
        Set<String> scopes,
        String traceId,
        String tokenId,
        int tokenBudgetLimit,
        int queryRateLimitPerMin,
        Map<String, String> attributes
) {

    public McpTenantContext {
        scopes = scopes == null ? Set.of() : Set.copyOf(scopes);
        attributes = attributes == null ? Map.of() : Map.copyOf(attributes);
    }

    /**
     * Checks whether the current context grants the specified OAuth 2.0 scope.
     */
    public boolean hasScope(String requiredScope) {
        return requiredScope == null || requiredScope.isBlank() || scopes.contains(requiredScope);
    }

    /**
     * Checks whether all specified scopes are present in this context.
     */
    public boolean hasAllScopes(Collection<String> requiredScopes) {
        if (requiredScopes == null || requiredScopes.isEmpty()) {
            return true;
        }
        for (String scope : requiredScopes) {
            if (!hasScope(scope)) {
                return false;
            }
        }
        return true;
    }

    /**
     * Checks whether at least one of the specified scopes is present in this context.
     */
    public boolean hasAnyScope(Collection<String> candidateScopes) {
        if (candidateScopes == null || candidateScopes.isEmpty()) {
            return true;
        }
        for (String scope : candidateScopes) {
            if (scope != null && !scope.isBlank() && scopes.contains(scope)) {
                return true;
            }
        }
        return false;
    }
}
