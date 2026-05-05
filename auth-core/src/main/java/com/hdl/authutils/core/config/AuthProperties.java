package com.hdl.authutils.core.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.time.Duration;
import java.util.List;

/**
 * Configuration properties for auth-lib.
 * Prefix: auth
 */
@Data
@ConfigurationProperties(prefix = "auth")
public class AuthProperties {

    private Jwt jwt = new Jwt();
    private Security security = new Security();

    @Data
    public static class Jwt {

        /**
         * Secret key for JWT signing (HS512).
         * MUST be at least 64 characters (512-bit).
         */
        private String secretKey;

        private AccessToken accessToken = new AccessToken();
        private RefreshToken refreshToken = new RefreshToken();

        @Data
        public static class AccessToken {
            /** Access token time-to-live. Default: 30 minutes. */
            private Duration ttl = Duration.ofMinutes(30);

            /** Where to read access token from. Default: HEADER. */
            private TokenSource source = TokenSource.HEADER;

            /** Cookie name when source is COOKIE or BOTH. */
            private String cookieName = "access_token";
        }

        @Data
        public static class RefreshToken {
            /** Refresh token time-to-live. Default: 7 days. */
            private Duration ttl = Duration.ofDays(7);

            /** Revocation strategy. Default: ROTATE. */
            private RefreshStrategy strategy = RefreshStrategy.ROTATE;

            /** Where to read refresh token from. Default: COOKIE. */
            private TokenSource source = TokenSource.COOKIE;

            /** Cookie name for refresh token. */
            private String cookieName = "refresh_token";

            /** HttpOnly flag — JS cannot access. Default: true. */
            private boolean cookieHttpOnly = true;

            /** Secure flag — only sent over HTTPS. Default: true. */
            private boolean cookieSecure = true;

            /** SameSite attribute. Default: Strict. */
            private String cookieSameSite = "Strict";

            /** Cookie path — restrict where browser sends cookie. Default: /auth/refresh. */
            private String cookiePath = "/auth/refresh";
        }
    }

    /**
     * Security config for default SecurityFilterChain.
     * Only used when project does NOT define its own SecurityFilterChain bean.
     */
    @Data
    public static class Security {

        /**
         * URL patterns to permit without authentication.
         * Default includes common public paths.
         */
        private List<String> whiteList = List.of(
                "/auth/**",
                "/public/**",
                "/swagger-ui/**",
                "/v3/api-docs/**",
                "/actuator/health"
        );

        private Cors cors = new Cors();

        @Data
        public static class Cors {
            /** Allowed origin patterns. Default: localhost any port. */
            private List<String> allowedOriginPatterns = List.of("http://localhost:*");

            /** Allowed HTTP methods. */
            private List<String> allowedMethods = List.of("GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS");

            /** Allowed headers. */
            private List<String> allowedHeaders = List.of("*");

            /** Allow credentials (cookies). MUST be true for refresh token cookie. Default: true. */
            private boolean allowCredentials = true;

            /** Preflight cache duration in seconds. Default: 3600. */
            private long maxAge = 3600;
        }
    }

    public enum TokenSource {
        HEADER, COOKIE, BOTH
    }

    public enum RefreshStrategy {
        ROTATE, FAMILY
    }
}
