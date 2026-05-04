package com.hdl.authutils.core.model;

import java.time.Instant;
import java.util.Map;
import java.util.Set;

/**
 * Parsed claims from a validated access token.
 */
public record TokenClaims(
        Long userId,
        String username,
        String displayName,
        Set<String> roles,
        Map<String, Object> additionalClaims,
        Instant issuedAt,
        Instant expiresAt
) {
}
