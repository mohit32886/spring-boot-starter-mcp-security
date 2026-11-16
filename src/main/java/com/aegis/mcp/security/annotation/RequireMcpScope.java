package com.aegis.mcp.security.annotation;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Declaratively enforces OAuth 2.0 scopes and capability attribution on MCP tool methods
 * or handler classes, emitting structured OpenTelemetry audit events on allow and deny outcomes.
 */
@Documented
@Target({ElementType.METHOD, ElementType.TYPE})
@Retention(RetentionPolicy.RUNTIME)
public @interface RequireMcpScope {

    /**
     * Required OAuth 2.0 scopes (e.g., {@code "k8s:logs:read"}).
     */
    String[] value() default {};

    /**
     * Evaluation mode when multiple scopes are specified.
     */
    LogicalMode mode() default LogicalMode.ALL;

    /**
     * Optional logical MCP tool name for audit attribution. Defaults to {@code ClassName.methodName}.
     */
    String toolName() default "";

    /**
     * Whether a non-blank {@code capability_id} claim is mandatory for invoking this tool.
     */
    boolean requireCapability() default true;
}
