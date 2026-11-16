package com.aegis.mcp.security.oauth2;

import com.aegis.mcp.security.config.McpSecurityProperties;
import com.aegis.mcp.security.context.McpTenantContext;
import com.aegis.mcp.security.exception.McpAccessDeniedException;
import com.aegis.mcp.security.exception.McpAuthenticationException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.Date;
import java.util.Set;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class McpJwtAssertionServiceTest {

    private McpSecurityProperties properties;
    private McpTokenReplayCache replayCache;
    private McpJwtAssertionService service;

    @BeforeEach
    void setUp() {
        properties = new McpSecurityProperties();
        properties.setIssuer("https://auth.test-mcp.local");
        properties.setAudience("mcp://cluster-prod");
        properties.setHmacSecret("super-secret-enterprise-hmac-key-for-unit-tests-2026");
        properties.setTokenTtlSeconds(300);
        properties.setClockSkewSeconds(10);

        McpSecurityProperties.ClientRegistration client = new McpSecurityProperties.ClientRegistration();
        client.setClientSecret("client-sre-agent-secret-987654321");
        client.setTenantId("tenant-acme");
        client.setAllowedScopes(Set.of("k8s:logs:read", "k8s:pods:restart"));
        properties.getClients().put("aegis-sre-agent", client);

        replayCache = new McpTokenReplayCache();
        service = new McpJwtAssertionService(properties, replayCache);
    }

    @Test
    void issuesAndVerifiesAccessTokenWithTenantClaims() {
        String token = service.issueAccessToken(
                "sre-triage-agent",
                "tenant-acme",
                "cap-k8s-diagnostics",
                Set.of("k8s:logs:read", "metrics:query"),
                "trace-abc-123",
                12000,
                120
        );

        McpTenantContext ctx = service.verifyAndExtractContext(token);

        assertThat(ctx.tenantId()).isEqualTo("tenant-acme");
        assertThat(ctx.capabilityId()).isEqualTo("cap-k8s-diagnostics");
        assertThat(ctx.subject()).isEqualTo("sre-triage-agent");
        assertThat(ctx.scopes()).containsExactlyInAnyOrder("k8s:logs:read", "metrics:query");
        assertThat(ctx.traceId()).isEqualTo("trace-abc-123");
        assertThat(ctx.tokenId()).isNotBlank();
        assertThat(ctx.tokenBudgetLimit()).isEqualTo(12000);
        assertThat(ctx.queryRateLimitPerMin()).isEqualTo(120);
    }

    @Test
    void rejectsReplayedAccessTokenWhenReplayProtectionEnabled() {
        String token = service.issueAccessToken(
                "agent-1", "tenant-acme", "cap-1", Set.of("read"), "trace-1", 1000, 10);

        service.verifyAndExtractContext(token);

        assertThatThrownBy(() -> service.verifyAndExtractContext(token))
                .isInstanceOf(McpAuthenticationException.class)
                .hasMessageContaining("replayed");
    }

    @Test
    void allowsTokenReuseWhenReplayProtectionDisabled() {
        properties.setReplayProtectionEnabled(false);
        service = new McpJwtAssertionService(properties, replayCache);

        String token = service.issueAccessToken(
                "agent-1", "tenant-acme", "cap-1", Set.of("read"), "trace-1", 1000, 10);

        assertThat(service.verifyAndExtractContext(token).tenantId()).isEqualTo("tenant-acme");
        assertThat(service.verifyAndExtractContext(token).tenantId()).isEqualTo("tenant-acme");
    }

    @Test
    void createsAndVerifiesRfc7523ClientAssertionAndBlocksReplay() {
        String assertion = service.createClientAssertion(
                "aegis-sre-agent", "client-sre-agent-secret-987654321");

        String verifiedClientId = service.verifyClientAssertion(assertion);
        assertThat(verifiedClientId).isEqualTo("aegis-sre-agent");

        assertThatThrownBy(() -> service.verifyClientAssertion(assertion))
                .isInstanceOf(McpAuthenticationException.class)
                .hasMessageContaining("replayed");
    }

    @Test
    void rejectsClientAssertionWithWrongSecret() {
        String assertion = service.createClientAssertion("aegis-sre-agent", "wrong-secret");

        assertThatThrownBy(() -> service.verifyClientAssertion(assertion))
                .isInstanceOf(McpAuthenticationException.class)
                .hasMessageContaining("signature");
    }

    @Test
    void attenuatesTokenScopesAndRejectsPrivilegeEscalation() throws Exception {
        String parentToken = service.issueAccessToken(
                "agent-1",
                "tenant-acme",
                "cap-db-reader",
                Set.of("db:select", "k8s:logs:read", "k8s:pods:restart"),
                "trace-chain-1",
                8000,
                60
        );
        McpTenantContext parentCtx = service.verifyAndExtractContext(parentToken);

        String attenuatedToken = service.exchangeForToolScopedToken(
                parentCtx,
                "mcp://cluster-prod",
                Set.of("k8s:logs:read"),
                60
        );

        SignedJWT parsed = SignedJWT.parse(attenuatedToken);
        assertThat(parsed.getJWTClaimsSet().getStringClaim("parent_jti")).isEqualTo(parentCtx.tokenId());

        McpTenantContext downstreamCtx = service.verifyAndExtractContext(attenuatedToken);
        assertThat(downstreamCtx.scopes()).containsExactly("k8s:logs:read");
        assertThat(downstreamCtx.tenantId()).isEqualTo("tenant-acme");
        assertThat(downstreamCtx.traceId()).isEqualTo("trace-chain-1");

        assertThatThrownBy(() -> service.exchangeForToolScopedToken(
                downstreamCtx,
                "mcp://cluster-prod",
                Set.of("k8s:logs:read", "admin:drop-cluster"),
                60
        ))
                .isInstanceOf(McpAccessDeniedException.class)
                .hasMessageContaining("exceed caller's granted scopes");
    }

    @Test
    void rejectsExpiredUntrustedIssuerAndMissingClaims() throws Exception {
        byte[] key = MessageDigest.getInstance("SHA-256")
                .digest(properties.getHmacSecret().getBytes(StandardCharsets.UTF_8));
        Instant now = Instant.now();

        // Expired beyond clock skew
        JWTClaimsSet expiredClaims = new JWTClaimsSet.Builder()
                .jwtID(UUID.randomUUID().toString())
                .issuer(properties.getIssuer())
                .audience(properties.getAudience())
                .subject("agent-1")
                .issueTime(Date.from(now.minusSeconds(300)))
                .expirationTime(Date.from(now.minusSeconds(60)))
                .claim("tenant_id", "tenant-acme")
                .claim("capability_id", "cap-1")
                .build();
        String expiredJwt = sign(expiredClaims, key);

        assertThatThrownBy(() -> service.verifyAndExtractContext(expiredJwt))
                .isInstanceOf(McpAuthenticationException.class)
                .hasMessageContaining("expired");

        // Wrong issuer
        JWTClaimsSet badIssuerClaims = new JWTClaimsSet.Builder()
                .jwtID(UUID.randomUUID().toString())
                .issuer("https://evil.attacker")
                .audience(properties.getAudience())
                .subject("agent-1")
                .issueTime(Date.from(now))
                .expirationTime(Date.from(now.plusSeconds(120)))
                .claim("tenant_id", "tenant-acme")
                .claim("capability_id", "cap-1")
                .build();
        String badIssuerJwt = sign(badIssuerClaims, key);

        assertThatThrownBy(() -> service.verifyAndExtractContext(badIssuerJwt))
                .isInstanceOf(McpAuthenticationException.class)
                .hasMessageContaining("issuer");

        // Missing capability_id
        JWTClaimsSet missingCapabilityClaims = new JWTClaimsSet.Builder()
                .jwtID(UUID.randomUUID().toString())
                .issuer(properties.getIssuer())
                .audience(properties.getAudience())
                .subject("agent-1")
                .issueTime(Date.from(now))
                .expirationTime(Date.from(now.plusSeconds(120)))
                .claim("tenant_id", "tenant-acme")
                .build();
        String missingCapJwt = sign(missingCapabilityClaims, key);

        assertThatThrownBy(() -> service.verifyAndExtractContext(missingCapJwt))
                .isInstanceOf(McpAuthenticationException.class)
                .hasMessageContaining("capability_id");
    }

    private static String sign(JWTClaimsSet claims, byte[] key) throws Exception {
        SignedJWT jwt = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.HS256).type(JOSEObjectType.JWT).build(),
                claims
        );
        jwt.sign(new MACSigner(key));
        return jwt.serialize();
    }
}
