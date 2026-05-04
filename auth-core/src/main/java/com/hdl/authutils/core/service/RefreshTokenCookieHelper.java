package com.hdl.authutils.core.service;

import com.hdl.authutils.core.config.AuthProperties;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.ResponseCookie;

import java.util.Optional;

/**
 * Utility to create, read, and delete refresh token cookies.
 * Reads config from AuthProperties.
 */
public class RefreshTokenCookieHelper {

    private final AuthProperties.Jwt.RefreshToken config;

    public RefreshTokenCookieHelper(AuthProperties properties) {
        this.config = properties.getJwt().getRefreshToken();
    }

    /**
     * Create a cookie containing the refresh token.
     * Use: response.addHeader(HttpHeaders.SET_COOKIE, createCookie(token).toString())
     */
    public ResponseCookie createCookie(String refreshToken) {
        return ResponseCookie.from(config.getCookieName(), refreshToken)
                .httpOnly(config.isCookieHttpOnly())
                .secure(config.isCookieSecure())
                .sameSite(config.getCookieSameSite())
                .path(config.getCookiePath())
                .maxAge(config.getTtl())
                .build();
    }

    /**
     * Create an expired cookie to delete the refresh token from browser.
     * Use on logout: response.addHeader(HttpHeaders.SET_COOKIE, createExpiredCookie().toString())
     */
    public ResponseCookie createExpiredCookie() {
        return ResponseCookie.from(config.getCookieName(), "")
                .httpOnly(config.isCookieHttpOnly())
                .secure(config.isCookieSecure())
                .sameSite(config.getCookieSameSite())
                .path(config.getCookiePath())
                .maxAge(0)
                .build();
    }

    /**
     * Extract refresh token value from request cookie.
     */
    public Optional<String> extractFromRequest(HttpServletRequest request) {
        Cookie[] cookies = request.getCookies();
        if (cookies == null) return Optional.empty();
        for (Cookie cookie : cookies) {
            if (config.getCookieName().equals(cookie.getName())) {
                String value = cookie.getValue();
                return (value != null && !value.isBlank()) ? Optional.of(value) : Optional.empty();
            }
        }
        return Optional.empty();
    }
}
