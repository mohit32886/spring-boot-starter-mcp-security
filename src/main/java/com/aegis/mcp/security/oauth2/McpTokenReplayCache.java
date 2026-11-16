package com.aegis.mcp.security.oauth2;

import java.time.Instant;
import java.util.Iterator;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Bounded, thread-safe in-memory replay cache tracking JWT IDs ({@code jti})
 * until their token expiration timestamp to mitigate token replay attacks.
 */
public class McpTokenReplayCache {

    private static final int DEFAULT_MAX_ENTRIES = 10_000;

    private final ConcurrentHashMap<String, Instant> seenTokens = new ConcurrentHashMap<>();
    private final int maxEntries;

    public McpTokenReplayCache() {
        this(DEFAULT_MAX_ENTRIES);
    }

    public McpTokenReplayCache(int maxEntries) {
        if (maxEntries <= 0) {
            throw new IllegalArgumentException("maxEntries must be positive");
        }
        this.maxEntries = maxEntries;
    }

    /**
     * Checks whether the given {@code jti} has already been observed and is still valid.
     * If unseen (or previously expired), records it until {@code expiresAt} and returns {@code true}.
     * If already seen and not yet expired, returns {@code false}.
     */
    public boolean checkAndRecord(String jti, Instant expiresAt) {
        if (jti == null || jti.isBlank()) {
            return false;
        }
        Instant now = Instant.now();
        Instant effectiveExpiry = expiresAt != null ? expiresAt : now.plusSeconds(300);

        if (seenTokens.size() >= maxEntries) {
            evictExpired(now);
            if (seenTokens.size() >= maxEntries) {
                evictOldest();
            }
        }

        final boolean[] accepted = {false};
        seenTokens.compute(jti, (key, existingExpiry) -> {
            if (existingExpiry == null || existingExpiry.isBefore(now)) {
                accepted[0] = true;
                return effectiveExpiry;
            }
            accepted[0] = false;
            return existingExpiry;
        });
        return accepted[0];
    }

    public int size() {
        return seenTokens.size();
    }

    public void clear() {
        seenTokens.clear();
    }

    private void evictExpired(Instant now) {
        seenTokens.entrySet().removeIf(entry -> entry.getValue().isBefore(now));
    }

    private void evictOldest() {
        Iterator<Map.Entry<String, Instant>> iterator = seenTokens.entrySet().iterator();
        int toRemove = Math.max(1, maxEntries / 10);
        int removed = 0;
        while (iterator.hasNext() && removed < toRemove) {
            iterator.next();
            iterator.remove();
            removed++;
        }
    }
}
