package com.hdl.authutils.oauth2.handler;

import com.hdl.authutils.oauth2.config.AuthOAuth2Properties;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

/**
 * Handles OAuth2 login failure by redirecting to FE callback URL with error parameter.
 * Uses the same redirect URL as success handler (auth.oauth2.redirect-url).
 */
public class OAuth2LoginFailureHandler implements AuthenticationFailureHandler {

    private static final Logger log = LoggerFactory.getLogger(OAuth2LoginFailureHandler.class);

    private final AuthOAuth2Properties properties;

    public OAuth2LoginFailureHandler(AuthOAuth2Properties properties) {
        this.properties = properties;
    }

    @Override
    public void onAuthenticationFailure(HttpServletRequest request,
                                        HttpServletResponse response,
                                        AuthenticationException exception)
            throws IOException {

        log.warn("OAuth2 login failed: {}", exception.getMessage());

        String baseUrl = properties.getRedirectUrl();
        if (baseUrl == null || baseUrl.isBlank()) {
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "OAuth2 login failed");
            return;
        }

        String errorMessage = exception.getMessage() != null
                ? exception.getMessage()
                : "authentication_failed";

        String redirectUrl = UriComponentsBuilder.fromUriString(baseUrl)
                .queryParam("error", URLEncoder.encode(errorMessage, StandardCharsets.UTF_8))
                .build().toUriString();

        response.sendRedirect(redirectUrl);
    }
}
