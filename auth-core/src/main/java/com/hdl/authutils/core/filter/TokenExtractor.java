package com.hdl.authutils.core.filter;

import com.hdl.authutils.core.config.AuthProperties;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;

import java.util.Optional;

/**
 * Extracts token from request based on configuration (header, cookie, or both).
 */
class TokenExtractor {

    private static final String AUTHORIZATION_HEADER = "Authorization";
    private static final String BEARER_PREFIX = "Bearer ";

    private final AuthProperties.TokenSource source;
    private final String cookieName;

    TokenExtractor(AuthProperties.TokenSource source, String cookieName) {
        this.source = source;
        this.cookieName = cookieName;
    }

    Optional<String> extract(HttpServletRequest request) {
        return switch (source) {
            case HEADER -> extractFromHeader(request);
            case COOKIE -> extractFromCookie(request);
            case BOTH -> extractFromHeader(request)
                    .or(() -> extractFromCookie(request));
        };
    }

    private Optional<String> extractFromHeader(HttpServletRequest request) {
        String header = request.getHeader(AUTHORIZATION_HEADER);
        if (header != null && header.startsWith(BEARER_PREFIX)) {
            String token = header.substring(BEARER_PREFIX.length()).trim();
            return token.isEmpty() ? Optional.empty() : Optional.of(token);
        }
        return Optional.empty();
    }

    private Optional<String> extractFromCookie(HttpServletRequest request) {
        Cookie[] cookies = request.getCookies();
        if (cookies == null) return Optional.empty();
        for (Cookie cookie : cookies) {
            if (cookieName.equals(cookie.getName())) {
                String value = cookie.getValue();
                return (value != null && !value.isBlank()) ? Optional.of(value) : Optional.empty();
            }
        }
        return Optional.empty();
    }
}
