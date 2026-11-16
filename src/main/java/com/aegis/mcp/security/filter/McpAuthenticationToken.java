package com.aegis.mcp.security.filter;

import com.aegis.mcp.security.context.McpTenantContext;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.Collection;
import java.util.Objects;

/**
 * Spring Security {@link org.springframework.security.core.Authentication} implementation
 * backed by a verified {@link McpTenantContext} and {@code SCOPE_*} authorities.
 */
public class McpAuthenticationToken extends AbstractAuthenticationToken {

    private final McpTenantContext tenantContext;

    public McpAuthenticationToken(McpTenantContext tenantContext) {
        super(toAuthorities(tenantContext));
        this.tenantContext = Objects.requireNonNull(tenantContext, "tenantContext must not be null");
        setAuthenticated(true);
    }

    private static Collection<? extends GrantedAuthority> toAuthorities(McpTenantContext context) {
        return context.scopes().stream()
                .map(scope -> new SimpleGrantedAuthority("SCOPE_" + scope))
                .toList();
    }

    @Override
    public Object getCredentials() {
        return "";
    }

    @Override
    public McpTenantContext getPrincipal() {
        return tenantContext;
    }

    @Override
    public String getName() {
        return tenantContext.subject() != null ? tenantContext.subject() : tenantContext.tenantId();
    }

    public McpTenantContext getTenantContext() {
        return tenantContext;
    }
}
