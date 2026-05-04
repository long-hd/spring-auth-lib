package com.hdl.authutils.core.service;

import com.hdl.authutils.core.config.AuthProperties;
import com.hdl.authutils.core.exception.AuthException;
import com.hdl.authutils.core.model.*;
import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.*;
import java.util.stream.Collectors;

/**
 * Default TokenService implementation using jjwt.
 * Supports both ROTATE and FAMILY refresh strategies.
 */
public class DefaultTokenService implements TokenService {

    private static final Logger log = LoggerFactory.getLogger(DefaultTokenService.class);

    // Standard claim keys
    static final String CLAIM_USERNAME = "username";
    static final String CLAIM_DISPLAY_NAME = "displayName";
    static final String CLAIM_ROLES = "roles";

    private final AuthProperties.Jwt jwtConfig;
    private final SecretKey signingKey;
    private final RefreshTokenStore refreshTokenStore;
    private final TokenClaimsEnricher claimsEnricher; // nullable

    public DefaultTokenService(AuthProperties properties,
                               RefreshTokenStore refreshTokenStore,
                               TokenClaimsEnricher claimsEnricher) {
        this.jwtConfig = properties.getJwt();
        this.signingKey = Keys.hmacShaKeyFor(
                jwtConfig.getSecretKey().getBytes(StandardCharsets.UTF_8));
        this.refreshTokenStore = refreshTokenStore;
        this.claimsEnricher = claimsEnricher;
    }

    @Override
    public TokenPair generateTokens(TokenRequest request) {
        Objects.requireNonNull(request.userId(), "userId must not be null");
        Objects.requireNonNull(request.username(), "username must not be null");

        Instant now = Instant.now();
        Instant accessExpiry = now.plus(jwtConfig.getAccessToken().getTtl());
        Instant refreshExpiry = now.plus(jwtConfig.getRefreshToken().getTtl());

        // Build claims
        Map<String, Object> claims = buildClaims(request);

        // Generate access token (JWT)
        String accessToken = buildJwt(request.userId(), claims, now, accessExpiry);

        // Generate refresh token (opaque UUID, stored in RefreshTokenStore)
        String refreshTokenValue = UUID.randomUUID().toString();

        // Family ID for FAMILY strategy
        String familyId = null;
        if (jwtConfig.getRefreshToken().getStrategy() == AuthProperties.RefreshStrategy.FAMILY) {
            familyId = UUID.randomUUID().toString();
        }

        RefreshToken refreshToken = RefreshToken.builder()
                .tokenValue(refreshTokenValue)
                .userId(request.userId())
                .familyId(familyId)
                .expiresAt(refreshExpiry)
                .createdAt(now)
                .revoked(false)
                .username(request.username())
                .displayName(request.displayName())
                .roles(request.roles())
                .additionalClaims(request.additionalClaims())
                .build();

        refreshTokenStore.save(refreshToken);

        // For ROTATE strategy: revoke all previous tokens for this user
        // (except the one we just saved)
        if (jwtConfig.getRefreshToken().getStrategy() == AuthProperties.RefreshStrategy.ROTATE) {
            revokeAllExcept(request.userId(), refreshTokenValue);
        }

        return new TokenPair(accessToken, refreshTokenValue, accessExpiry, refreshExpiry);
    }

    @Override
    public Optional<TokenClaims> validateAccessToken(String token) {
        try {
            Claims claims = Jwts.parser()
                    .verifyWith(signingKey)
                    .build()
                    .parseSignedClaims(token)
                    .getPayload();

            return Optional.of(parseClaims(claims));
        } catch (ExpiredJwtException e) {
            log.debug("Access token expired: {}", e.getMessage());
            return Optional.empty();
        } catch (JwtException e) {
            log.debug("Invalid access token: {}", e.getMessage());
            return Optional.empty();
        }
    }

    @Override
    public TokenPair refresh(String refreshTokenValue) {
        RefreshToken stored = refreshTokenStore.findByToken(refreshTokenValue)
                .orElseThrow(() -> new AuthException("Refresh token not found"));

        // Check if revoked — possible token theft
        if (stored.revoked()) {
            handleRevokedTokenReuse(stored);
            throw new AuthException("Refresh token has been revoked");
        }

        // Check expiry
        if (stored.isExpired()) {
            throw new AuthException("Refresh token expired");
        }

        // Revoke the used token
        refreshTokenStore.revokeByToken(refreshTokenValue);

        Instant now = Instant.now();
        Instant accessExpiry = now.plus(jwtConfig.getAccessToken().getTtl());
        Instant refreshExpiry = now.plus(jwtConfig.getRefreshToken().getTtl());

        // We need user info to generate new access token.
        // For refresh, we re-encode from stored userId.
        // The access token claims come from the ORIGINAL login — we don't re-query DB.
        // This is by design: if user's roles changed, they need to re-login.
        // However, we need at least userId to generate a minimal access token.
        // The proper approach: encode essential claims in the refresh token's associated data.
        // For now, generate a minimal JWT with just userId.
        // Project can override this by providing a custom TokenService.

        String newRefreshTokenValue = UUID.randomUUID().toString();

        // Preserve family ID for FAMILY strategy
        String familyId = stored.familyId();
        if (jwtConfig.getRefreshToken().getStrategy() == AuthProperties.RefreshStrategy.FAMILY
                && familyId == null) {
            familyId = UUID.randomUUID().toString();
        }

        RefreshToken newRefreshToken = RefreshToken.builder()
                .tokenValue(newRefreshTokenValue)
                .userId(stored.userId())
                .familyId(familyId)
                .expiresAt(refreshExpiry)
                .createdAt(now)
                .revoked(false)
                .username(stored.username())
                .displayName(stored.displayName())
                .roles(stored.roles())
                .additionalClaims(stored.additionalClaims())
                .build();

        refreshTokenStore.save(newRefreshToken);

        // For ROTATE strategy: revoke all other tokens for this user
        if (jwtConfig.getRefreshToken().getStrategy() == AuthProperties.RefreshStrategy.ROTATE) {
            revokeAllExcept(stored.userId(), newRefreshTokenValue);
        }

        // Rebuild full access token from stored claims
        TokenRequest rebuiltRequest = TokenRequest.builder()
                .userId(stored.userId())
                .username(stored.username())
                .displayName(stored.displayName())
                .roles(stored.roles() != null ? stored.roles() : Set.of())
                .additionalClaims(stored.additionalClaims() != null ? stored.additionalClaims() : Map.of())
                .build();

        Map<String, Object> claims = buildClaims(rebuiltRequest);
        String newAccessToken = buildJwt(stored.userId(), claims, now, accessExpiry);

        return new TokenPair(newAccessToken, newRefreshTokenValue, accessExpiry, refreshExpiry);
    }

    @Override
    public void revokeRefreshToken(String refreshToken) {
        refreshTokenStore.revokeByToken(refreshToken);
    }

    @Override
    public void revokeAllByUserId(Long userId) {
        refreshTokenStore.revokeAllByUserId(userId);
    }

    // ── Private helpers ─────────────────────────────────────

    private Map<String, Object> buildClaims(TokenRequest request) {
        Map<String, Object> claims = new LinkedHashMap<>();

        // Standard claims
        claims.put(CLAIM_USERNAME, request.username());
        if (request.displayName() != null) {
            claims.put(CLAIM_DISPLAY_NAME, request.displayName());
        }
        if (request.roles() != null && !request.roles().isEmpty()) {
            claims.put(CLAIM_ROLES, request.roles());
        }

        // Additional claims from request
        if (request.additionalClaims() != null) {
            claims.putAll(request.additionalClaims());
        }

        // Enricher hook
        if (claimsEnricher != null) {
            Map<String, Object> enriched = claimsEnricher.enrich(request);
            if (enriched != null) {
                claims.putAll(enriched);
            }
        }

        return claims;
    }

    private String buildJwt(Long userId, Map<String, Object> claims,
                            Instant issuedAt, Instant expiry) {
        return Jwts.builder()
                .subject(String.valueOf(userId))
                .claims(claims)
                .issuedAt(Date.from(issuedAt))
                .expiration(Date.from(expiry))
                .signWith(signingKey, Jwts.SIG.HS512)
                .compact();
    }

    private TokenClaims parseClaims(Claims jwtClaims) {
        Long userId = Long.parseLong(jwtClaims.getSubject());
        String username = jwtClaims.get(CLAIM_USERNAME, String.class);
        String displayName = jwtClaims.get(CLAIM_DISPLAY_NAME, String.class);

        // Parse roles
        Set<String> roles = Set.of();
        Object rolesObj = jwtClaims.get(CLAIM_ROLES);
        if (rolesObj instanceof Collection<?> rolesList) {
            roles = rolesList.stream()
                    .map(String::valueOf)
                    .collect(Collectors.toUnmodifiableSet());
        }

        // Collect additional claims (everything except standard ones)
        Set<String> standardKeys = Set.of(
                "sub", "iat", "exp", CLAIM_USERNAME, CLAIM_DISPLAY_NAME, CLAIM_ROLES
        );
        Map<String, Object> additionalClaims = new LinkedHashMap<>();
        for (Map.Entry<String, Object> entry : jwtClaims.entrySet()) {
            if (!standardKeys.contains(entry.getKey())) {
                additionalClaims.put(entry.getKey(), entry.getValue());
            }
        }

        return new TokenClaims(
                userId, username, displayName, roles,
                Collections.unmodifiableMap(additionalClaims),
                jwtClaims.getIssuedAt().toInstant(),
                jwtClaims.getExpiration().toInstant()
        );
    }

    /**
     * For ROTATE strategy: revoke all refresh tokens for a user except the given one.
     */
    private void revokeAllExcept(Long userId, String exceptTokenValue) {
        // InMemoryStore doesn't have a "revoke all except" method,
        // so we revoke all, then re-save the exception.
        // For DB-backed stores, this would be a single UPDATE query.
        refreshTokenStore.findByToken(exceptTokenValue).ifPresent(keep -> {
            refreshTokenStore.revokeAllByUserId(userId);
            // Re-save the one we want to keep (un-revoked)
            refreshTokenStore.save(keep);
        });
    }

    /**
     * Handle reuse of a revoked refresh token — potential token theft.
     * For FAMILY strategy: revoke entire family (all devices in that login session).
     */
    private void handleRevokedTokenReuse(RefreshToken revokedToken) {
        if (jwtConfig.getRefreshToken().getStrategy() == AuthProperties.RefreshStrategy.FAMILY
                && revokedToken.familyId() != null) {
            log.warn("Refresh token reuse detected for user {} in family {}. "
                            + "Revoking entire token family (possible token theft).",
                    revokedToken.userId(), revokedToken.familyId());
            refreshTokenStore.revokeAllByFamily(revokedToken.familyId());
        } else {
            log.warn("Revoked refresh token reuse detected for user {}.", revokedToken.userId());
        }
    }
}
