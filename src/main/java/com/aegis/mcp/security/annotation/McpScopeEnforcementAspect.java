package com.aegis.mcp.security.annotation;

import com.aegis.mcp.security.audit.McpAuditTrailService;
import com.aegis.mcp.security.context.McpTenantContext;
import com.aegis.mcp.security.context.McpTenantContextHolder;
import com.aegis.mcp.security.exception.McpAccessDeniedException;
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.reflect.MethodSignature;
import org.springframework.core.annotation.AnnotatedElementUtils;

import java.lang.reflect.Method;
import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * AOP aspect that intercepts methods or classes annotated with {@link RequireMcpScope},
 * enforces capability attribution and OAuth 2.0 scope requirements against the active
 * {@link McpTenantContextHolder}, and emits OpenTelemetry tool invocation audit events.
 */
@Aspect
public class McpScopeEnforcementAspect {

    private final McpAuditTrailService auditTrailService;

    public McpScopeEnforcementAspect(McpAuditTrailService auditTrailService) {
        this.auditTrailService = auditTrailService;
    }

    @Around("@annotation(com.aegis.mcp.security.annotation.RequireMcpScope) "
            + "|| @within(com.aegis.mcp.security.annotation.RequireMcpScope)")
    public Object enforceScope(ProceedingJoinPoint joinPoint) throws Throwable {
        long startNanos = System.nanoTime();
        MethodSignature signature = (MethodSignature) joinPoint.getSignature();
        Method method = signature.getMethod();
        Class<?> targetClass = joinPoint.getTarget() != null
                ? joinPoint.getTarget().getClass()
                : method.getDeclaringClass();

        RequireMcpScope annotation = resolveAnnotation(method, targetClass);
        if (annotation == null) {
            return joinPoint.proceed();
        }

        String toolName = (annotation.toolName() != null && !annotation.toolName().isBlank())
                ? annotation.toolName()
                : targetClass.getSimpleName() + "." + method.getName();

        Set<String> requiredScopes = Arrays.stream(annotation.value())
                .filter(s -> s != null && !s.isBlank())
                .collect(Collectors.toCollection(LinkedHashSet::new));

        McpTenantContext context = McpTenantContextHolder.get().orElse(null);
        if (context == null) {
            long elapsedMs = elapsedMillis(startNanos);
            String reason = "Missing McpTenantContext for tool invocation: " + toolName;
            auditTrailService.recordToolInvocationDeny(null, toolName, requiredScopes, reason, elapsedMs);
            throw new McpAccessDeniedException(reason, requiredScopes, Set.of());
        }

        if (annotation.requireCapability()
                && (context.capabilityId() == null || context.capabilityId().isBlank())) {
            long elapsedMs = elapsedMillis(startNanos);
            String reason = "Missing required capability_id for MCP tool: " + toolName;
            auditTrailService.recordToolInvocationDeny(context, toolName, requiredScopes, reason, elapsedMs);
            throw new McpAccessDeniedException(reason, requiredScopes, context.scopes());
        }

        boolean authorized = annotation.mode() == LogicalMode.ANY
                ? context.hasAnyScope(requiredScopes)
                : context.hasAllScopes(requiredScopes);

        if (!authorized) {
            long elapsedMs = elapsedMillis(startNanos);
            String reason = "Insufficient MCP scopes for tool '" + toolName
                    + "': required=" + requiredScopes + " (" + annotation.mode() + "), granted=" + context.scopes();
            auditTrailService.recordToolInvocationDeny(context, toolName, requiredScopes, reason, elapsedMs);
            throw new McpAccessDeniedException(reason, requiredScopes, context.scopes());
        }

        try {
            return joinPoint.proceed();
        } finally {
            auditTrailService.recordToolInvocationAllow(
                    context,
                    toolName,
                    requiredScopes,
                    elapsedMillis(startNanos)
            );
        }
    }

    private static RequireMcpScope resolveAnnotation(Method method, Class<?> targetClass) {
        RequireMcpScope methodAnnotation = AnnotatedElementUtils.findMergedAnnotation(method, RequireMcpScope.class);
        if (methodAnnotation != null) {
            return methodAnnotation;
        }
        return AnnotatedElementUtils.findMergedAnnotation(targetClass, RequireMcpScope.class);
    }

    private static long elapsedMillis(long startNanos) {
        return (System.nanoTime() - startNanos) / 1_000_000L;
    }
}
