package com.hdl.authutils.core.model;

import lombok.Builder;

import java.time.Instant;
import java.util.Map;
import java.util.Set;

/**
 * Refresh token domain object, stored in RefreshTokenStore.
 * <p>
 * Stores original claims so that refresh can rebuild a full access token
 * without re-querying the database.
 */
@Builder
public record RefreshToken(
        String tokenValue,
        Long userId,
        String familyId,        // null if using ROTATE strategy
        Instant expiresAt,
        Instant createdAt,
        boolean revoked,

        // Original claims — used to rebuild access token on refresh
        String username,
        String displayName,
        Set<String> roles,
        Map<String, Object> additionalClaims
) {

    public boolean isExpired() {
        return Instant.now().isAfter(expiresAt);
    }

    public boolean isUsable() {
        return !revoked && !isExpired();
    }
}
