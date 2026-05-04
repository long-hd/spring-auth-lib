package com.hdl.authutils.core.model;

import java.time.Instant;

/**
 * Pair of access + refresh token returned after login or refresh.
 */
public record TokenPair(
        String accessToken,
        String refreshToken,
        Instant accessTokenExpiresAt,
        Instant refreshTokenExpiresAt
) {
}
