package com.aegis.mcp.security.autoconfigure;

import com.aegis.mcp.security.annotation.McpScopeEnforcementAspect;
import com.aegis.mcp.security.audit.InMemoryMcpAuditSink;
import com.aegis.mcp.security.audit.McpAuditExporter;
import com.aegis.mcp.security.audit.McpAuditTrailService;
import com.aegis.mcp.security.audit.OpenTelemetryMcpAuditExporter;
import com.aegis.mcp.security.config.McpSecurityProperties;
import com.aegis.mcp.security.context.McpTenantClientHttpRequestInterceptor;
import com.aegis.mcp.security.context.McpTenantTaskDecorator;
import com.aegis.mcp.security.exception.McpAccessDeniedException;
import com.aegis.mcp.security.filter.McpJwtAuthenticationFilter;
import com.aegis.mcp.security.oauth2.McpJwtAssertionService;
import com.aegis.mcp.security.oauth2.McpTokenReplayCache;
import io.micrometer.core.instrument.MeterRegistry;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.client.ClientHttpRequestInterceptor;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.List;

/**
 * Spring Boot 3 Auto-Configuration for {@code spring-boot-starter-mcp-security}.
 * Wires OAuth 2.0 JWT assertion handling, replay cache, tenant context propagation,
 * OpenTelemetry audit exporters, AOP scope enforcement, and servlet security filtering.
 */
@AutoConfiguration
@EnableConfigurationProperties(McpSecurityProperties.class)
@ConditionalOnProperty(prefix = "mcp.security", name = "enabled", havingValue = "true", matchIfMissing = true)
public class McpSecurityAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean
    public McpTokenReplayCache mcpTokenReplayCache() {
        return new McpTokenReplayCache();
    }

    @Bean
    @ConditionalOnMissingBean
    public McpJwtAssertionService mcpJwtAssertionService(
            McpSecurityProperties properties,
            McpTokenReplayCache replayCache
    ) {
        return new McpJwtAssertionService(properties, replayCache);
    }

    @Bean
    @ConditionalOnMissingBean
    public OpenTelemetryMcpAuditExporter openTelemetryMcpAuditExporter(
            ObjectProvider<MeterRegistry> meterRegistryProvider
    ) {
        return new OpenTelemetryMcpAuditExporter(meterRegistryProvider.getIfAvailable());
    }

    @Bean
    @ConditionalOnMissingBean
    public InMemoryMcpAuditSink inMemoryMcpAuditSink() {
        return new InMemoryMcpAuditSink();
    }

    @Bean
    @ConditionalOnMissingBean
    public McpAuditTrailService mcpAuditTrailService(ObjectProvider<McpAuditExporter> exportersProvider) {
        return new McpAuditTrailService(exportersProvider.orderedStream().toList());
    }

    @Bean
    @ConditionalOnMissingBean
    public McpScopeEnforcementAspect mcpScopeEnforcementAspect(McpAuditTrailService auditTrailService) {
        return new McpScopeEnforcementAspect(auditTrailService);
    }

    @Bean
    @ConditionalOnMissingBean
    public McpTenantTaskDecorator mcpTenantTaskDecorator() {
        return new McpTenantTaskDecorator();
    }

    @Configuration(proxyBeanMethods = false)
    @ConditionalOnClass(ClientHttpRequestInterceptor.class)
    static class McpRestClientConfiguration {

        @Bean
        @ConditionalOnMissingBean
        public McpTenantClientHttpRequestInterceptor mcpTenantClientHttpRequestInterceptor() {
            return new McpTenantClientHttpRequestInterceptor();
        }
    }

    @Configuration(proxyBeanMethods = false)
    @ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
    @ConditionalOnClass({OncePerRequestFilter.class, SecurityFilterChain.class})
    static class McpWebSecurityConfiguration {

        @Bean
        @ConditionalOnMissingBean
        public McpJwtAuthenticationFilter mcpJwtAuthenticationFilter(
                McpSecurityProperties properties,
                McpJwtAssertionService assertionService,
                McpAuditTrailService auditTrailService
        ) {
            return new McpJwtAuthenticationFilter(properties, assertionService, auditTrailService);
        }

        @Bean(name = "mcpJwtAuthenticationFilterRegistration")
        @ConditionalOnMissingBean(name = "mcpJwtAuthenticationFilterRegistration")
        public FilterRegistrationBean<McpJwtAuthenticationFilter> mcpJwtAuthenticationFilterRegistration(
                McpJwtAuthenticationFilter filter
        ) {
            FilterRegistrationBean<McpJwtAuthenticationFilter> registration = new FilterRegistrationBean<>(filter);
            registration.setEnabled(false);
            return registration;
        }

        @Bean(name = "mcpSecurityFilterChain")
        @Order(Ordered.HIGHEST_PRECEDENCE + 50)
        @ConditionalOnMissingBean(name = "mcpSecurityFilterChain")
        public SecurityFilterChain mcpSecurityFilterChain(
                HttpSecurity http,
                McpSecurityProperties properties,
                McpJwtAuthenticationFilter mcpJwtAuthenticationFilter
        ) throws Exception {
            List<String> patterns = properties.getProtectedPathPatterns();
            if (patterns == null || patterns.isEmpty()) {
                http.securityMatcher(request -> false);
            } else {
                http.securityMatcher(patterns.toArray(String[]::new));
            }

            return http
                    .csrf(AbstractHttpConfigurer::disable)
                    .sessionManagement(sm -> sm.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                    .authorizeHttpRequests(auth -> auth.anyRequest().authenticated())
                    .exceptionHandling(ex -> ex
                            .authenticationEntryPoint((request, response, authException) ->
                                    writeErrorResponse(
                                            response,
                                            HttpStatus.UNAUTHORIZED,
                                            "invalid_token",
                                            authException.getMessage(),
                                            "Bearer error=\"invalid_token\""
                                    ))
                            .accessDeniedHandler((request, response, accessDeniedException) -> {
                                String wwwAuth = "Bearer error=\"insufficient_scope\"";
                                if (accessDeniedException instanceof McpAccessDeniedException mcpEx
                                        && !mcpEx.getRequiredScopes().isEmpty()) {
                                    wwwAuth += ", scope=\"" + String.join(" ", mcpEx.getRequiredScopes()) + "\"";
                                }
                                writeErrorResponse(
                                        response,
                                        HttpStatus.FORBIDDEN,
                                        "insufficient_scope",
                                        accessDeniedException.getMessage(),
                                        wwwAuth
                                );
                            })
                    )
                    .addFilterBefore(mcpJwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
                    .build();
        }

        private static void writeErrorResponse(
                HttpServletResponse response,
                HttpStatus status,
                String error,
                String message,
                String wwwAuthenticate
        ) throws IOException {
            response.setStatus(status.value());
            if (wwwAuthenticate != null && !wwwAuthenticate.isBlank()) {
                response.setHeader(HttpHeaders.WWW_AUTHENTICATE, wwwAuthenticate);
            }
            response.setContentType(MediaType.APPLICATION_JSON_VALUE);
            response.setCharacterEncoding(StandardCharsets.UTF_8.name());
            String safeMessage = message == null ? status.getReasonPhrase() : message;
            String body = "{\"error\":\"" + escapeJson(error) + "\",\"message\":\"" + escapeJson(safeMessage) + "\"}";
            response.getWriter().write(body);
        }

        private static String escapeJson(String value) {
            return value.replace("\\", "\\\\")
                    .replace("\"", "\\\"")
                    .replace("\r", " ")
                    .replace("\n", " ");
        }
    }
}
