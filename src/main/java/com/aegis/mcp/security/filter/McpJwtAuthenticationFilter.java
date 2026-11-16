package com.aegis.mcp.security.filter;

import com.aegis.mcp.security.audit.McpAuditTrailService;
import com.aegis.mcp.security.config.McpSecurityProperties;
import com.aegis.mcp.security.context.McpTenantContext;
import com.aegis.mcp.security.context.McpTenantContextHolder;
import com.aegis.mcp.security.exception.McpAuthenticationException;
import com.aegis.mcp.security.oauth2.McpJwtAssertionService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.util.AntPathMatcher;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.List;

/**
 * Servlet filter that authenticates incoming MCP requests matching {@code mcp.security.protected-path-patterns}
 * via OAuth 2.0 Bearer JWT assertions, binds {@link McpTenantContextHolder} and {@link SecurityContextHolder},
 * emits OpenTelemetry audit events, and guarantees context cleanup after request completion.
 */
public class McpJwtAuthenticationFilter extends OncePerRequestFilter {

    private static final String BEARER_PREFIX = "Bearer ";

    private final McpSecurityProperties properties;
    private final McpJwtAssertionService assertionService;
    private final McpAuditTrailService auditTrailService;
    private final AntPathMatcher pathMatcher = new AntPathMatcher();

    public McpJwtAuthenticationFilter(
            McpSecurityProperties properties,
            McpJwtAssertionService assertionService,
            McpAuditTrailService auditTrailService
    ) {
        this.properties = properties;
        this.assertionService = assertionService;
        this.auditTrailService = auditTrailService;
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        List<String> patterns = properties.getProtectedPathPatterns();
        if (patterns == null || patterns.isEmpty()) {
            return true;
        }
        String path = resolveApplicationPath(request);
        for (String pattern : patterns) {
            if (pattern != null && !pattern.isBlank() && pathMatcher.match(pattern, path)) {
                return false;
            }
        }
        return true;
    }

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain
    ) throws ServletException, IOException {
        long startNanos = System.nanoTime();
        String requestUri = request.getRequestURI();
        String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);

        if (authHeader == null || !authHeader.startsWith(BEARER_PREFIX)) {
            long elapsedMs = (System.nanoTime() - startNanos) / 1_000_000L;
            String reason = "Missing or malformed Authorization Bearer header";
            auditTrailService.recordAuthenticationDeny(requestUri, reason, elapsedMs);
            writeUnauthorized(response, "invalid_request", reason);
            return;
        }

        String token = authHeader.substring(BEARER_PREFIX.length()).trim();
        McpTenantContext context;
        try {
            context = assertionService.verifyAndExtractContext(token);
        } catch (McpAuthenticationException ex) {
            long elapsedMs = (System.nanoTime() - startNanos) / 1_000_000L;
            auditTrailService.recordAuthenticationDeny(requestUri, ex.getMessage(), elapsedMs);
            writeUnauthorized(response, "invalid_token", ex.getMessage());
            return;
        }

        long authLatencyMs = (System.nanoTime() - startNanos) / 1_000_000L;
        auditTrailService.recordAuthenticationAllow(context, requestUri, authLatencyMs);

        McpTenantContextHolder.set(context);
        SecurityContextHolder.getContext().setAuthentication(new McpAuthenticationToken(context));
        try {
            filterChain.doFilter(request, response);
        } finally {
            McpTenantContextHolder.clear();
            SecurityContextHolder.clearContext();
        }
    }

    private static String resolveApplicationPath(HttpServletRequest request) {
        String requestUri = request.getRequestURI();
        String contextPath = request.getContextPath();
        if (contextPath != null && !contextPath.isEmpty() && requestUri.startsWith(contextPath)) {
            return requestUri.substring(contextPath.length());
        }
        return requestUri;
    }

    private static void writeUnauthorized(HttpServletResponse response, String error, String description)
            throws IOException {
        String sanitizedDesc = sanitizeHeaderValue(description);
        response.setStatus(HttpStatus.UNAUTHORIZED.value());
        response.setHeader(
                HttpHeaders.WWW_AUTHENTICATE,
                "Bearer error=\"" + error + "\", error_description=\"" + sanitizedDesc + "\""
        );
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setCharacterEncoding(StandardCharsets.UTF_8.name());
        String body = "{\"error\":\"" + escapeJson(error) + "\",\"message\":\"" + escapeJson(description) + "\"}";
        response.getWriter().write(body);
    }

    private static String sanitizeHeaderValue(String value) {
        if (value == null) {
            return "";
        }
        return value.replace("\"", "'").replaceAll("[\\r\\n]", " ");
    }

    private static String escapeJson(String value) {
        if (value == null) {
            return "";
        }
        return value.replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\r", " ")
                .replace("\n", " ");
    }
}
