package com.hdl.authutils.oauth2.handler;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.jackson2.SecurityJackson2Modules;
import org.springframework.security.oauth2.client.jackson2.OAuth2ClientJackson2Module;
import org.springframework.security.oauth2.client.web.AuthorizationRequestRepository;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

/**
 * Stores OAuth2 authorization request in an encrypted cookie instead of HTTP session.
 * <p>
 * Required for stateless (STATELESS session policy) OAuth2 flow.
 * Without this, the OAuth2 "state" parameter validation fails because
 * there's no session to store the original authorization request.
 * <p>
 * Flow:
 * <ol>
 *   <li>User clicks "Login with Google" → redirect to /oauth2/authorization/google</li>
 *   <li>Spring Security creates OAuth2AuthorizationRequest (contains state, nonce)</li>
 *   <li>This repo saves it in a cookie</li>
 *   <li>Browser redirects to Google → user logs in → Google redirects back</li>
 *   <li>Spring Security reads cookie, validates state parameter</li>
 *   <li>This repo removes the cookie</li>
 * </ol>
 */
public class CookieOAuth2AuthorizationRequestRepository
        implements AuthorizationRequestRepository<OAuth2AuthorizationRequest> {

    private static final Logger log =
            LoggerFactory.getLogger(CookieOAuth2AuthorizationRequestRepository.class);

    private static final String COOKIE_NAME = "oauth2_auth_request";
    private static final int COOKIE_EXPIRE_SECONDS = 180; // 3 minutes
    private static final String SAME_SITE_ATTRIBUTE = "SameSite";
    private static final String SAME_SITE_VALUE = "Lax";

    /**
     * Jackson mapper configured with Spring Security modules so it can
     * (de)serialize {@link OAuth2AuthorizationRequest} safely without
     * relying on Java native serialization.
     */
    private static final ObjectMapper MAPPER = buildMapper();

    private static ObjectMapper buildMapper() {
        ObjectMapper mapper = new ObjectMapper();
        ClassLoader classLoader = CookieOAuth2AuthorizationRequestRepository.class.getClassLoader();
        mapper.registerModules(SecurityJackson2Modules.getModules(classLoader));
        mapper.registerModule(new OAuth2ClientJackson2Module());
        return mapper;
    }

    @Override
    public OAuth2AuthorizationRequest loadAuthorizationRequest(HttpServletRequest request) {
        return getCookieValue(request);
    }

    @Override
    public void saveAuthorizationRequest(OAuth2AuthorizationRequest authorizationRequest,
                                         HttpServletRequest request,
                                         HttpServletResponse response) {
        if (authorizationRequest == null) {
            removeCookie(response);
            return;
        }

        String encoded;
        try {
            byte[] json = MAPPER.writeValueAsBytes(authorizationRequest);
            encoded = Base64.getUrlEncoder().encodeToString(json);
        } catch (JsonProcessingException e) {
            throw new IllegalStateException("Failed to serialize OAuth2AuthorizationRequest", e);
        }

        Cookie cookie = new Cookie(COOKIE_NAME, encoded);
        cookie.setPath("/");
        cookie.setHttpOnly(true);
        cookie.setSecure(request.isSecure());
        cookie.setMaxAge(COOKIE_EXPIRE_SECONDS);
        cookie.setAttribute(SAME_SITE_ATTRIBUTE, SAME_SITE_VALUE);
        response.addCookie(cookie);
    }

    @Override
    public OAuth2AuthorizationRequest removeAuthorizationRequest(
            HttpServletRequest request, HttpServletResponse response) {
        OAuth2AuthorizationRequest authRequest = getCookieValue(request);
        if (authRequest != null) {
            removeCookie(response);
        }
        return authRequest;
    }

    private OAuth2AuthorizationRequest getCookieValue(HttpServletRequest request) {
        Cookie[] cookies = request.getCookies();
        if (cookies == null) return null;

        for (Cookie cookie : cookies) {
            if (COOKIE_NAME.equals(cookie.getName())) {
                try {
                    byte[] decoded = Base64.getUrlDecoder().decode(cookie.getValue());
                    String json = new String(decoded, StandardCharsets.UTF_8);
                    return MAPPER.readValue(json, OAuth2AuthorizationRequest.class);
                } catch (IllegalArgumentException e) {
                    log.warn("OAuth2 auth request cookie has invalid Base64 payload");
                    return null;
                } catch (Exception e) {
                    log.warn("Failed to deserialize OAuth2 auth request cookie: {}", e.getMessage());
                    return null;
                }
            }
        }
        return null;
    }

    private void removeCookie(HttpServletResponse response) {
        Cookie cookie = new Cookie(COOKIE_NAME, "");
        cookie.setPath("/");
        cookie.setHttpOnly(true);
        cookie.setMaxAge(0);
        cookie.setAttribute(SAME_SITE_ATTRIBUTE, SAME_SITE_VALUE);
        response.addCookie(cookie);
    }
}
