package com.aegis.mcp.security.context;

import com.aegis.mcp.security.oauth2.McpJwtAssertionService;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpRequest;
import org.springframework.http.client.ClientHttpRequestExecution;
import org.springframework.http.client.ClientHttpRequestInterceptor;
import org.springframework.http.client.ClientHttpResponse;

import java.io.IOException;
import java.util.Set;

/**
 * {@link ClientHttpRequestInterceptor} that propagates tenant identity, capability attribution,
 * trace correlation headers, and optionally an attenuated downstream OAuth 2.0 Bearer token
 * from the active {@link McpTenantContextHolder} onto outbound HTTP calls.
 */
public class McpTenantClientHttpRequestInterceptor implements ClientHttpRequestInterceptor {

    public static final String HEADER_TENANT_ID = "X-Tenant-Id";
    public static final String HEADER_CAPABILITY_ID = "X-Capability-Id";
    public static final String HEADER_TRACE_ID = "X-Trace-Id";

    private final McpJwtAssertionService assertionService;
    private final boolean propagateAttenuatedToken;
    private final String targetAudience;
    private final Set<String> downstreamScopes;
    private final int downstreamTtlSeconds;

    public McpTenantClientHttpRequestInterceptor() {
        this(null, false, null, null, 60);
    }

    public McpTenantClientHttpRequestInterceptor(
            McpJwtAssertionService assertionService,
            boolean propagateAttenuatedToken,
            String targetAudience,
            Set<String> downstreamScopes,
            int downstreamTtlSeconds
    ) {
        this.assertionService = assertionService;
        this.propagateAttenuatedToken = propagateAttenuatedToken;
        this.targetAudience = targetAudience;
        this.downstreamScopes = downstreamScopes;
        this.downstreamTtlSeconds = downstreamTtlSeconds;
    }

    @Override
    public ClientHttpResponse intercept(
            HttpRequest request,
            byte[] body,
            ClientHttpRequestExecution execution
    ) throws IOException {
        McpTenantContextHolder.get().ifPresent(context -> {
            HttpHeaders headers = request.getHeaders();
            setHeaderIfPresent(headers, HEADER_TENANT_ID, context.tenantId());
            setHeaderIfPresent(headers, HEADER_CAPABILITY_ID, context.capabilityId());
            setHeaderIfPresent(headers, HEADER_TRACE_ID, context.traceId());

            if (propagateAttenuatedToken
                    && assertionService != null
                    && !headers.containsKey(HttpHeaders.AUTHORIZATION)) {
                String token = assertionService.exchangeForToolScopedToken(
                        context,
                        targetAudience,
                        downstreamScopes,
                        downstreamTtlSeconds
                );
                headers.setBearerAuth(token);
            }
        });
        return execution.execute(request, body);
    }

    private static void setHeaderIfPresent(HttpHeaders headers, String name, String value) {
        if (value != null && !value.isBlank() && !headers.containsKey(name)) {
            headers.set(name, value);
        }
    }
}
