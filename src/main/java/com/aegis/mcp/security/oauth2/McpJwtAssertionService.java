package com.aegis.mcp.security.oauth2;

import com.aegis.mcp.security.config.McpSecurityProperties;
import com.aegis.mcp.security.context.McpTenantContext;
import com.aegis.mcp.security.exception.McpAccessDeniedException;
import com.aegis.mcp.security.exception.McpAuthenticationException;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.text.ParseException;
import java.time.Instant;
import java.util.Arrays;
import java.util.Date;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

/**
 * Issues, exchanges, and verifies OAuth 2.0 JWT access tokens and RFC 7523 {@code jwt-bearer}
 * client assertions carrying tenant, capability, trace, and compute budget claims.
 */
public class McpJwtAssertionService {

    public static final String JWT_BEARER_ASSERTION_TYPE =
            "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

    private static final Logger log = LoggerFactory.getLogger(McpJwtAssertionService.class);

    private final McpSecurityProperties properties;
    private final McpTokenReplayCache replayCache;
    private final byte[] signingKey;

    public McpJwtAssertionService(McpSecurityProperties properties, McpTokenReplayCache replayCache) {
        this.properties = properties;
        this.replayCache = replayCache;
        this.signingKey = derive256BitKey(properties.getHmacSecret());
        if (McpSecurityProperties.DEFAULT_DEV_HMAC_SECRET.equals(properties.getHmacSecret())) {
            log.warn("MCP Security is using the default development HMAC secret. Configure 'mcp.security.hmac-secret' in production.");
        }
    }

    /**
     * Mints an OAuth 2.0 access token JWT bound to a specific tenant, capability ID, and scopes.
     */
    public String issueAccessToken(
            String subject,
            String tenantId,
            String capabilityId,
            Set<String> scopes,
            String traceId,
            int tokenBudgetLimit,
            int qpmLimit
    ) {
        return issueTokenInternal(
                subject,
                tenantId,
                capabilityId,
                scopes,
                traceId,
                tokenBudgetLimit,
                qpmLimit,
                properties.getAudience(),
                properties.getTokenTtlSeconds(),
                null
        );
    }

    /**
     * Mints an RFC 7523 signed client assertion JWT for OAuth 2.0 {@code client_credentials} token exchange.
     */
    public String createClientAssertion(String clientId, String clientSecret) {
        if (clientId == null || clientId.isBlank()) {
            throw new IllegalArgumentException("clientId must not be blank");
        }
        if (clientSecret == null || clientSecret.isBlank()) {
            throw new IllegalArgumentException("clientSecret must not be blank");
        }
        Instant now = Instant.now();
        byte[] clientKey = derive256BitKey(clientSecret);

        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .jwtID(UUID.randomUUID().toString())
                .issuer(clientId)
                .subject(clientId)
                .audience(properties.getIssuer() + "/oauth2/token")
                .issueTime(Date.from(now))
                .expirationTime(Date.from(now.plusSeconds(120)))
                .build();

        try {
            SignedJWT jwt = new SignedJWT(
                    new JWSHeader.Builder(JWSAlgorithm.HS256).type(JOSEObjectType.JWT).build(),
                    claims
            );
            jwt.sign(new MACSigner(clientKey));
            return jwt.serialize();
        } catch (JOSEException e) {
            throw new IllegalStateException("Failed to sign RFC 7523 client assertion JWT", e);
        }
    }

    /**
     * Verifies a signed RFC 7523 {@code jwt-bearer} client assertion against configured client registrations,
     * clock skew, audience, and replay protection.
     */
    public String verifyClientAssertion(String assertionJwt) {
        if (assertionJwt == null || assertionJwt.isBlank()) {
            throw new McpAuthenticationException("Missing client_assertion JWT");
        }
        try {
            SignedJWT signedJwt = SignedJWT.parse(assertionJwt);
            JWTClaimsSet claims = signedJwt.getJWTClaimsSet();
            String clientId = claims.getSubject();
            if (clientId == null || clientId.isBlank() || !clientId.equals(claims.getIssuer())) {
                throw new McpAuthenticationException(
                        "Invalid client_assertion: subject and issuer must match client_id");
            }

            McpSecurityProperties.ClientRegistration registration = properties.getClients().get(clientId);
            if (registration == null || registration.getClientSecret() == null) {
                throw new McpAuthenticationException("Unknown or misconfigured OAuth 2.0 client: " + clientId);
            }

            byte[] clientKey = derive256BitKey(registration.getClientSecret());
            if (!signedJwt.verify(new MACVerifier(clientKey))) {
                throw new McpAuthenticationException("Invalid client_assertion signature for client: " + clientId);
            }

            Instant now = Instant.now();
            long skew = Math.max(0L, properties.getClockSkewSeconds());
            Date exp = claims.getExpirationTime();
            if (exp == null || exp.toInstant().plusSeconds(skew).isBefore(now)) {
                throw new McpAuthenticationException("Expired client_assertion for client: " + clientId);
            }
            Date iat = claims.getIssueTime();
            if (iat != null && iat.toInstant().minusSeconds(skew).isAfter(now)) {
                throw new McpAuthenticationException("Client assertion issued-at time is in the future");
            }

            List<String> audiences = claims.getAudience();
            String expectedTokenAud = properties.getIssuer() + "/oauth2/token";
            if (audiences == null || (!audiences.contains(expectedTokenAud)
                    && !audiences.contains(properties.getIssuer()))) {
                throw new McpAuthenticationException("Invalid client_assertion audience");
            }

            if (properties.isReplayProtectionEnabled()) {
                String jti = claims.getJWTID();
                if (jti == null || jti.isBlank()) {
                    throw new McpAuthenticationException("Missing required jti claim in client_assertion");
                }
                if (!replayCache.checkAndRecord(jti, exp.toInstant().plusSeconds(skew))) {
                    throw new McpAuthenticationException("Detected replayed client_assertion jti: " + jti);
                }
            }

            return clientId;
        } catch (ParseException | JOSEException e) {
            throw new McpAuthenticationException("Malformed client_assertion JWT", e);
        }
    }

    /**
     * Validates an incoming MCP bearer access token and extracts its {@link McpTenantContext}.
     */
    public McpTenantContext verifyAndExtractContext(String bearerToken) {
        if (bearerToken == null || bearerToken.isBlank()) {
            throw new McpAuthenticationException("Missing bearer JWT");
        }
        try {
            SignedJWT signedJwt = SignedJWT.parse(bearerToken);
            if (!signedJwt.verify(new MACVerifier(signingKey))) {
                throw new McpAuthenticationException("Invalid JWT signature");
            }

            JWTClaimsSet claims = signedJwt.getJWTClaimsSet();
            Instant now = Instant.now();
            long skew = Math.max(0L, properties.getClockSkewSeconds());

            Date expiration = claims.getExpirationTime();
            if (expiration == null || expiration.toInstant().plusSeconds(skew).isBefore(now)) {
                throw new McpAuthenticationException("JWT access token has expired");
            }
            Date issuedAt = claims.getIssueTime();
            if (issuedAt != null && issuedAt.toInstant().minusSeconds(skew).isAfter(now)) {
                throw new McpAuthenticationException("JWT access token issued-at time is in the future");
            }

            if (!properties.getIssuer().equals(claims.getIssuer())) {
                throw new McpAuthenticationException("Untrusted JWT issuer: " + claims.getIssuer());
            }

            List<String> audience = claims.getAudience();
            if (audience == null || !audience.contains(properties.getAudience())) {
                throw new McpAuthenticationException("Invalid JWT audience for MCP server");
            }

            String jti = claims.getJWTID();
            if (properties.isReplayProtectionEnabled()) {
                if (jti == null || jti.isBlank()) {
                    throw new McpAuthenticationException("Missing required jti claim for replay protection");
                }
                if (!replayCache.checkAndRecord(jti, expiration.toInstant().plusSeconds(skew))) {
                    throw new McpAuthenticationException("Detected replayed JWT token jti: " + jti);
                }
            }

            String tenantId = claims.getStringClaim("tenant_id");
            if (tenantId == null || tenantId.isBlank()) {
                throw new McpAuthenticationException("Missing required tenant_id claim in JWT");
            }

            String capabilityId = claims.getStringClaim("capability_id");
            if (properties.isRequireCapabilityClaim() && (capabilityId == null || capabilityId.isBlank())) {
                throw new McpAuthenticationException("Missing required capability_id claim in JWT");
            }

            String scopeStr = claims.getStringClaim("scope");
            Set<String> scopes = (scopeStr == null || scopeStr.isBlank())
                    ? Set.of()
                    : Arrays.stream(scopeStr.split("\\s+"))
                            .filter(s -> !s.isBlank())
                            .collect(Collectors.toUnmodifiableSet());

            String traceId = claims.getStringClaim("trace_id");
            Number tokenBudgetNum = (Number) claims.getClaim("token_budget");
            Number qpmLimitNum = (Number) claims.getClaim("qpm_limit");
            int tokenBudget = tokenBudgetNum != null
                    ? tokenBudgetNum.intValue()
                    : properties.getDefaultTokenBudget();
            int qpmLimit = qpmLimitNum != null
                    ? qpmLimitNum.intValue()
                    : properties.getDefaultQpmLimit();

            return new McpTenantContext(
                    tenantId,
                    capabilityId,
                    claims.getSubject(),
                    scopes,
                    (traceId == null || traceId.isBlank()) ? UUID.randomUUID().toString() : traceId,
                    jti,
                    tokenBudget,
                    qpmLimit,
                    Map.of()
            );
        } catch (ParseException | JOSEException e) {
            throw new McpAuthenticationException("Invalid JWT token format", e);
        }
    }

    /**
     * RFC 8693-style scope attenuation: exchanges an authenticated {@link McpTenantContext} for a
     * short-lived, least-privilege token bound to {@code targetAudience} and {@code narrowedScopes}.
     * Rejects privilege escalation if any requested scope is not present in {@code parentContext}.
     */
    public String exchangeForToolScopedToken(
            McpTenantContext parentContext,
            String targetAudience,
            Set<String> narrowedScopes,
            int ttlSeconds
    ) {
        if (parentContext == null) {
            throw new McpAuthenticationException("Cannot exchange token without an active McpTenantContext");
        }
        Set<String> effectiveScopes = narrowedScopes == null
                ? parentContext.scopes()
                : narrowedScopes.stream()
                        .filter(s -> s != null && !s.isBlank())
                        .collect(Collectors.toCollection(LinkedHashSet::new));

        if (!parentContext.scopes().containsAll(effectiveScopes)) {
            throw new McpAccessDeniedException(
                    "Token exchange rejected: requested scopes exceed caller's granted scopes",
                    effectiveScopes,
                    parentContext.scopes()
            );
        }

        String effectiveAudience = (targetAudience == null || targetAudience.isBlank())
                ? properties.getAudience()
                : targetAudience;
        long effectiveTtl = ttlSeconds > 0 ? ttlSeconds : properties.getTokenTtlSeconds();

        return issueTokenInternal(
                parentContext.subject(),
                parentContext.tenantId(),
                parentContext.capabilityId(),
                effectiveScopes,
                parentContext.traceId(),
                parentContext.tokenBudgetLimit(),
                parentContext.queryRateLimitPerMin(),
                effectiveAudience,
                effectiveTtl,
                parentContext.tokenId()
        );
    }

    private String issueTokenInternal(
            String subject,
            String tenantId,
            String capabilityId,
            Set<String> scopes,
            String traceId,
            int tokenBudgetLimit,
            int qpmLimit,
            String audience,
            long ttlSeconds,
            String parentTokenId
    ) {
        Instant now = Instant.now();
        Instant expiresAt = now.plusSeconds(ttlSeconds);
        String scopeClaim = String.join(" ", scopes == null ? Set.of() : scopes);

        JWTClaimsSet.Builder builder = new JWTClaimsSet.Builder()
                .jwtID(UUID.randomUUID().toString())
                .issuer(properties.getIssuer())
                .audience(audience)
                .subject(subject)
                .issueTime(Date.from(now))
                .expirationTime(Date.from(expiresAt))
                .claim("tenant_id", tenantId)
                .claim("capability_id", capabilityId)
                .claim("agent_id", subject)
                .claim("scope", scopeClaim)
                .claim("trace_id", (traceId == null || traceId.isBlank()) ? UUID.randomUUID().toString() : traceId)
                .claim("token_budget", tokenBudgetLimit)
                .claim("qpm_limit", qpmLimit);

        if (parentTokenId != null && !parentTokenId.isBlank()) {
            builder.claim("parent_jti", parentTokenId);
        }

        return signClaims(builder.build());
    }

    private String signClaims(JWTClaimsSet claims) {
        try {
            JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.HS256)
                    .type(JOSEObjectType.JWT)
                    .build();
            SignedJWT signedJWT = new SignedJWT(header, claims);
            signedJWT.sign(new MACSigner(signingKey));
            return signedJWT.serialize();
        } catch (JOSEException e) {
            throw new IllegalStateException("Failed to sign JWT token", e);
        }
    }

    private static byte[] derive256BitKey(String secret) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return digest.digest((secret == null ? "" : secret).getBytes(StandardCharsets.UTF_8));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }
}
