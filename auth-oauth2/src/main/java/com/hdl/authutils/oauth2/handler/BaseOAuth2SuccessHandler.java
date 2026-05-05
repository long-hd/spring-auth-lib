package com.hdl.authutils.oauth2.handler;

import com.hdl.authutils.core.model.TokenPair;
import com.hdl.authutils.core.model.TokenRequest;
import com.hdl.authutils.core.service.RefreshTokenCookieHelper;
import com.hdl.authutils.core.service.TokenService;
import com.hdl.authutils.oauth2.config.AuthOAuth2Properties;
import com.hdl.authutils.oauth2.mapper.DefaultOidcUserInfoMapper;
import com.hdl.authutils.oauth2.mapper.OAuth2UserInfoMapper;
import com.hdl.authutils.oauth2.model.OAuth2UserInfo;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.IOException;
import java.util.List;

/**
 * Abstract OAuth2 success handler. Project MUST extend this and provide
 * a bean that builds the TokenRequest from OAuth2UserInfo.
 * <p>
 * Flow:
 * <ol>
 *   <li>Spring Security handles OAuth2 redirect + code exchange</li>
 *   <li>This handler receives the authenticated OAuth2User</li>
 *   <li>Finds the right mapper for the provider</li>
 *   <li>Calls {@link #buildTokenRequest(OAuth2UserInfo)} — project implements</li>
 *   <li>Generates JWT token pair</li>
 *   <li>Sets refresh token cookie</li>
 *   <li>Redirects to FE with access token</li>
 * </ol>
 * <p>
 * Usage:
 * <pre>
 * {@literal @}Component
 * public class AppOAuth2SuccessHandler extends BaseOAuth2SuccessHandler {
 *     {@literal @}Override
 *     protected TokenRequest buildTokenRequest(OAuth2UserInfo userInfo) {
 *         User user = userRepo.findByEmail(userInfo.email())
 *             .orElseGet(() -> createUser(userInfo));
 *         return TokenRequest.builder()
 *             .userId(user.getId())
 *             .username(user.getUsername())
 *             .roles(roleRepo.findNamesByUserId(user.getId()))
 *             .build();
 *     }
 * }
 * </pre>
 */
public abstract class BaseOAuth2SuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    private static final Logger log = LoggerFactory.getLogger(BaseOAuth2SuccessHandler.class);

    private final TokenService tokenService;
    private final RefreshTokenCookieHelper cookieHelper;
    private final List<OAuth2UserInfoMapper> mappers;
    private final AuthOAuth2Properties oAuth2Properties;

    protected BaseOAuth2SuccessHandler(TokenService tokenService,
                                       RefreshTokenCookieHelper cookieHelper,
                                       List<OAuth2UserInfoMapper> mappers,
                                       AuthOAuth2Properties oAuth2Properties) {
        this.tokenService = tokenService;
        this.cookieHelper = cookieHelper;
        this.mappers = mappers;
        this.oAuth2Properties = oAuth2Properties;
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request,
                                        HttpServletResponse response,
                                        Authentication authentication)
            throws IOException, ServletException {

        if (!(authentication instanceof OAuth2AuthenticationToken oauthToken)) {
            log.warn("Expected OAuth2AuthenticationToken but got: {}", authentication.getClass());
            super.onAuthenticationSuccess(request, response, authentication);
            return;
        }

        OAuth2User oAuth2User = oauthToken.getPrincipal();
        String registrationId = oauthToken.getAuthorizedClientRegistrationId();

        // Map provider response to standardized user info
        OAuth2UserInfo userInfo = findMapper(registrationId).map(oAuth2User, registrationId);

        // Project builds the TokenRequest (lookup/create local user, set roles, claims)
        TokenRequest tokenRequest = buildTokenRequest(userInfo);

        // Generate token pair
        TokenPair tokens = tokenService.generateTokens(tokenRequest);

        // Set refresh token cookie
        response.addHeader(HttpHeaders.SET_COOKIE,
                cookieHelper.createCookie(tokens.refreshToken()).toString());

        // Redirect to FE
        String redirectUrl = buildRedirectUrl(tokens, request);
        getRedirectStrategy().sendRedirect(request, response, redirectUrl);
    }

    /**
     * Project MUST implement — map OAuth2 user info to TokenRequest.
     * This is where the project looks up or creates a local user,
     * loads roles, and adds any additional claims.
     */
    protected abstract TokenRequest buildTokenRequest(OAuth2UserInfo userInfo);

    /**
     * Build redirect URL after OAuth2 success.
     * Default: reads from auth.oauth2.redirect-url config, appends token params.
     * Override if you need different redirect logic per provider.
     */
    protected String buildRedirectUrl(TokenPair tokens, HttpServletRequest request) {
        String baseUrl = oAuth2Properties.getRedirectUrl();
        if (baseUrl == null || baseUrl.isBlank()) {
            throw new IllegalStateException(
                    "auth.oauth2.redirect-url must be configured when using auth-oauth2 module");
        }
        return UriComponentsBuilder.fromUriString(baseUrl)
                .queryParam("token", tokens.accessToken())
                .queryParam("expires_at", tokens.accessTokenExpiresAt().toEpochMilli())
                .build().toUriString();
    }

    /**
     * Find the right mapper for this provider.
     * Project-defined mappers (supports() == true) take priority over the default.
     */
    private OAuth2UserInfoMapper findMapper(String registrationId) {
        // Project-specific mappers first (non-default)
        for (OAuth2UserInfoMapper mapper : mappers) {
            if (!(mapper instanceof DefaultOidcUserInfoMapper)
                    && mapper.supports(registrationId)) {
                return mapper;
            }
        }
        // Fallback to default
        for (OAuth2UserInfoMapper mapper : mappers) {
            if (mapper.supports(registrationId)) {
                return mapper;
            }
        }
        throw new IllegalStateException(
                "No OAuth2UserInfoMapper found for provider: " + registrationId);
    }
}
