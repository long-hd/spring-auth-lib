package com.hdl.authutils.core.config;

import java.time.Duration;

/**
 * Validates AuthProperties at startup. Fails fast on invalid config.
 */
class AuthPropertiesValidator {

    private static final int MIN_SECRET_KEY_LENGTH = 64;

    AuthPropertiesValidator(AuthProperties properties) {
        validate(properties);
    }

    private void validate(AuthProperties properties) {
        var jwt = properties.getJwt();

        // Secret key
        if (jwt.getSecretKey() == null || jwt.getSecretKey().isBlank()) {
            throw new IllegalStateException(
                    "auth.jwt.secret-key must not be blank");
        }
        if (jwt.getSecretKey().length() < MIN_SECRET_KEY_LENGTH) {
            throw new IllegalStateException(
                    "auth.jwt.secret-key must be at least " + MIN_SECRET_KEY_LENGTH
                            + " characters (512-bit for HS512), got " + jwt.getSecretKey().length());
        }

        // Access token TTL
        Duration accessTtl = jwt.getAccessToken().getTtl();
        if (accessTtl == null || accessTtl.isZero() || accessTtl.isNegative()) {
            throw new IllegalStateException(
                    "auth.jwt.access-token.ttl must be positive");
        }
        if (accessTtl.compareTo(Duration.ofHours(24)) > 0) {
            throw new IllegalStateException(
                    "auth.jwt.access-token.ttl must not exceed 24 hours, got " + accessTtl);
        }

        // Refresh token TTL
        Duration refreshTtl = jwt.getRefreshToken().getTtl();
        if (refreshTtl == null || refreshTtl.isZero() || refreshTtl.isNegative()) {
            throw new IllegalStateException(
                    "auth.jwt.refresh-token.ttl must be positive");
        }
        if (refreshTtl.compareTo(accessTtl) <= 0) {
            throw new IllegalStateException(
                    "auth.jwt.refresh-token.ttl must be greater than access-token.ttl");
        }

        // Cookie path
        String cookiePath = jwt.getRefreshToken().getCookiePath();
        if (cookiePath != null && !cookiePath.startsWith("/")) {
            throw new IllegalStateException(
                    "auth.jwt.refresh-token.cookie-path must start with '/'");
        }
    }
}
