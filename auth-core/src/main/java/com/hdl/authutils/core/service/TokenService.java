package com.hdl.authutils.core.service;

import com.hdl.authutils.core.model.TokenClaims;
import com.hdl.authutils.core.model.TokenPair;
import com.hdl.authutils.core.model.TokenRequest;

import java.util.Optional;

/**
 * Central service for token lifecycle: generate, validate, refresh, revoke.
 */
public interface TokenService {

    /**
     * Generate access + refresh token pair.
     */
    TokenPair generateTokens(TokenRequest request);

    /**
     * Validate an access token and parse its claims.
     * Returns empty if token is invalid, expired, or malformed.
     */
    Optional<TokenClaims> validateAccessToken(String token);

    /**
     * Refresh: validate refresh token, issue new token pair.
     * Old refresh token is revoked (rotate) or replaced (family).
     */
    TokenPair refresh(String refreshToken);

    /**
     * Revoke a single refresh token.
     */
    void revokeRefreshToken(String refreshToken);

    /**
     * Revoke ALL refresh tokens for a user (force logout all devices).
     */
    void revokeAllByUserId(Long userId);
}
