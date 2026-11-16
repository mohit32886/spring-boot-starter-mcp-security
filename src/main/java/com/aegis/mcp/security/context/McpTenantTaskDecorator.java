package com.aegis.mcp.security.context;

import org.slf4j.MDC;
import org.springframework.core.task.TaskDecorator;

import java.util.Map;

/**
 * Spring {@link TaskDecorator} that snapshots and restores {@link McpTenantContext}
 * and SLF4J {@link MDC} entries across async and virtual thread executors.
 */
public class McpTenantTaskDecorator implements TaskDecorator {

    @Override
    public Runnable decorate(Runnable runnable) {
        McpTenantContext capturedContext = McpTenantContextHolder.get().orElse(null);
        Map<String, String> capturedMdc = MDC.getCopyOfContextMap();

        return () -> {
            McpTenantContext previousContext = McpTenantContextHolder.get().orElse(null);
            Map<String, String> previousMdc = MDC.getCopyOfContextMap();
            try {
                if (capturedMdc != null) {
                    MDC.setContextMap(capturedMdc);
                } else {
                    MDC.clear();
                }
                McpTenantContextHolder.set(capturedContext);
                runnable.run();
            } finally {
                if (previousMdc != null) {
                    MDC.setContextMap(previousMdc);
                } else {
                    MDC.clear();
                }
                if (previousContext != null) {
                    McpTenantContextHolder.set(previousContext);
                } else {
                    McpTenantContextHolder.clear();
                }
            }
        };
    }
}
