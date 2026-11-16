package com.aegis.mcp.security.context;

import org.slf4j.MDC;

import java.util.Optional;
import java.util.concurrent.Callable;

/**
 * Propagates {@link McpTenantContext} across request threads, virtual threads, and async tasks,
 * while automatically synchronizing tenant and trace attributes into SLF4J {@link MDC}.
 */
public final class McpTenantContextHolder {

    public static final String MDC_TENANT_ID = "mcp.tenant_id";
    public static final String MDC_CAPABILITY_ID = "mcp.capability_id";
    public static final String MDC_SUBJECT = "mcp.subject";
    public static final String MDC_TRACE_ID = "mcp.trace_id";

    private static final InheritableThreadLocal<McpTenantContext> CONTEXT = new InheritableThreadLocal<>();

    private McpTenantContextHolder() {
    }

    public static void set(McpTenantContext context) {
        if (context == null) {
            CONTEXT.remove();
            clearMdc();
        } else {
            CONTEXT.set(context);
            syncMdc(context);
        }
    }

    public static Optional<McpTenantContext> get() {
        return Optional.ofNullable(CONTEXT.get());
    }

    public static McpTenantContext require() {
        McpTenantContext ctx = CONTEXT.get();
        if (ctx == null) {
            throw new IllegalStateException("McpTenantContext is missing from the current execution scope");
        }
        return ctx;
    }

    public static void clear() {
        CONTEXT.remove();
        clearMdc();
    }

    public static <T> T callWithContext(McpTenantContext context, Callable<T> action) {
        McpTenantContext previous = CONTEXT.get();
        set(context);
        try {
            return action.call();
        } catch (RuntimeException e) {
            throw e;
        } catch (Exception e) {
            throw new IllegalStateException("Scoped MCP tenant execution failed", e);
        } finally {
            set(previous);
        }
    }

    public static void runWithContext(McpTenantContext context, Runnable action) {
        McpTenantContext previous = CONTEXT.get();
        set(context);
        try {
            action.run();
        } finally {
            set(previous);
        }
    }

    /**
     * Wraps a {@link Runnable} so that it executes with the caller's current {@link McpTenantContext}
     * and restores the worker thread's previous context upon completion.
     */
    public static Runnable wrap(Runnable task) {
        McpTenantContext captured = CONTEXT.get();
        return () -> runWithContext(captured, task);
    }

    /**
     * Wraps a {@link Callable} so that it executes with the caller's current {@link McpTenantContext}
     * and restores the worker thread's previous context upon completion.
     */
    public static <T> Callable<T> wrap(Callable<T> task) {
        McpTenantContext captured = CONTEXT.get();
        return () -> callWithContext(captured, task);
    }

    private static void syncMdc(McpTenantContext context) {
        putOrRemoveMdc(MDC_TENANT_ID, context.tenantId());
        putOrRemoveMdc(MDC_CAPABILITY_ID, context.capabilityId());
        putOrRemoveMdc(MDC_SUBJECT, context.subject());
        putOrRemoveMdc(MDC_TRACE_ID, context.traceId());
    }

    private static void putOrRemoveMdc(String key, String value) {
        if (value == null || value.isBlank()) {
            MDC.remove(key);
        } else {
            MDC.put(key, value);
        }
    }

    private static void clearMdc() {
        MDC.remove(MDC_TENANT_ID);
        MDC.remove(MDC_CAPABILITY_ID);
        MDC.remove(MDC_SUBJECT);
        MDC.remove(MDC_TRACE_ID);
    }
}
