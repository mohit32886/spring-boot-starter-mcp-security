package com.aegis.mcp.security.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Configuration properties for securing Model Context Protocol (MCP) servers
 * with OAuth 2.0 JWT assertions, tenant context propagation, and OpenTelemetry audit trails.
 */
@ConfigurationProperties(prefix = "mcp.security")
public class McpSecurityProperties {

    public static final String DEFAULT_DEV_HMAC_SECRET =
            "aegis-mcp-security-dev-signing-secret-change-in-production-256bit";

    /**
     * Master toggle for MCP security auto-configuration.
     */
    private boolean enabled = true;

    /**
     * Expected OAuth 2.0 JWT issuer (iss claim).
     */
    private String issuer = "https://auth.aegis-mcp.internal";

    /**
     * Expected OAuth 2.0 JWT audience (aud claim) identifying this MCP server cluster.
     */
    private String audience = "mcp://enterprise-tool-cluster";

    /**
     * Shared HMAC-SHA256 signing secret used to mint and verify MCP JWT access tokens.
     * Override with a high-entropy secret in production.
     */
    private String hmacSecret = DEFAULT_DEV_HMAC_SECRET;

    /**
     * Lifetime in seconds for minted MCP access tokens.
     */
    private long tokenTtlSeconds = 300L;

    /**
     * Allowed clock skew in seconds when validating token expiration (exp) and issued-at (iat) claims.
     */
    private long clockSkewSeconds = 30L;

    /**
     * Enables jti (JWT ID) replay protection to prevent single-use token or assertion replay attacks.
     */
    private boolean replayProtectionEnabled = true;

    /**
     * Requires incoming JWT assertions to contain a non-blank capability_id claim.
     */
    private boolean requireCapabilityClaim = true;

    /**
     * Default per-window LLM/tool token budget assigned when the token omits a token_budget claim.
     */
    private int defaultTokenBudget = 8000;

    /**
     * Default per-minute query rate limit assigned when the token omits a qpm_limit claim.
     */
    private int defaultQpmLimit = 60;

    /**
     * Ant-style URL path patterns secured by the MCP JWT authentication filter.
     */
    private List<String> protectedPathPatterns = new ArrayList<>(List.of("/mcp/**", "/v1/mcp/**"));

    /**
     * Registered OAuth 2.0 clients authorized for RFC 7523 jwt-bearer client assertions.
     */
    private Map<String, ClientRegistration> clients = new LinkedHashMap<>();

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public String getIssuer() {
        return issuer;
    }

    public void setIssuer(String issuer) {
        this.issuer = issuer;
    }

    public String getAudience() {
        return audience;
    }

    public void setAudience(String audience) {
        this.audience = audience;
    }

    public String getHmacSecret() {
        return hmacSecret;
    }

    public void setHmacSecret(String hmacSecret) {
        this.hmacSecret = hmacSecret;
    }

    public long getTokenTtlSeconds() {
        return tokenTtlSeconds;
    }

    public void setTokenTtlSeconds(long tokenTtlSeconds) {
        this.tokenTtlSeconds = tokenTtlSeconds;
    }

    public long getClockSkewSeconds() {
        return clockSkewSeconds;
    }

    public void setClockSkewSeconds(long clockSkewSeconds) {
        this.clockSkewSeconds = clockSkewSeconds;
    }

    public boolean isReplayProtectionEnabled() {
        return replayProtectionEnabled;
    }

    public void setReplayProtectionEnabled(boolean replayProtectionEnabled) {
        this.replayProtectionEnabled = replayProtectionEnabled;
    }

    public boolean isRequireCapabilityClaim() {
        return requireCapabilityClaim;
    }

    public void setRequireCapabilityClaim(boolean requireCapabilityClaim) {
        this.requireCapabilityClaim = requireCapabilityClaim;
    }

    public int getDefaultTokenBudget() {
        return defaultTokenBudget;
    }

    public void setDefaultTokenBudget(int defaultTokenBudget) {
        this.defaultTokenBudget = defaultTokenBudget;
    }

    public int getDefaultQpmLimit() {
        return defaultQpmLimit;
    }

    public void setDefaultQpmLimit(int defaultQpmLimit) {
        this.defaultQpmLimit = defaultQpmLimit;
    }

    public List<String> getProtectedPathPatterns() {
        return protectedPathPatterns;
    }

    public void setProtectedPathPatterns(List<String> protectedPathPatterns) {
        this.protectedPathPatterns = protectedPathPatterns == null
                ? new ArrayList<>()
                : new ArrayList<>(protectedPathPatterns);
    }

    public Map<String, ClientRegistration> getClients() {
        return clients;
    }

    public void setClients(Map<String, ClientRegistration> clients) {
        this.clients = clients == null ? new LinkedHashMap<>() : new LinkedHashMap<>(clients);
    }

    /**
     * OAuth 2.0 confidential client configuration for RFC 7523 client assertion verification.
     */
    public static class ClientRegistration {
        private String clientSecret;
        private String tenantId;
        private Set<String> allowedScopes = new LinkedHashSet<>();

        public String getClientSecret() {
            return clientSecret;
        }

        public void setClientSecret(String clientSecret) {
            this.clientSecret = clientSecret;
        }

        public String getTenantId() {
            return tenantId;
        }

        public void setTenantId(String tenantId) {
            this.tenantId = tenantId;
        }

        public Set<String> getAllowedScopes() {
            return allowedScopes;
        }

        public void setAllowedScopes(Set<String> allowedScopes) {
            this.allowedScopes = allowedScopes == null
                    ? new LinkedHashSet<>()
                    : new LinkedHashSet<>(allowedScopes);
        }
    }
}
