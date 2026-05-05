package com.hdl.authutils.oauth2.config;

import com.hdl.authutils.core.config.HttpSecurityCustomizer;
import com.hdl.authutils.oauth2.handler.BaseOAuth2SuccessHandler;
import com.hdl.authutils.oauth2.handler.CookieOAuth2AuthorizationRequestRepository;
import com.hdl.authutils.oauth2.handler.OAuth2LoginFailureHandler;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;

/**
 * Customizer that adds OAuth2 login to the default SecurityFilterChain.
 * <p>
 * Only active when project provides a {@link BaseOAuth2SuccessHandler} bean.
 * Adds:
 * <ul>
 *   <li>.oauth2Login() with success/failure handlers</li>
 *   <li>Cookie-based authorization request repository (for stateless sessions)</li>
 *   <li>Permit /oauth2/authorization/** and /login/oauth2/code/** endpoints</li>
 * </ul>
 */
class OAuth2SecurityCustomizer implements HttpSecurityCustomizer {

    private static final Logger log = LoggerFactory.getLogger(OAuth2SecurityCustomizer.class);

    private final BaseOAuth2SuccessHandler successHandler;
    private final OAuth2LoginFailureHandler failureHandler;
    private final CookieOAuth2AuthorizationRequestRepository authRequestRepository;

    OAuth2SecurityCustomizer(BaseOAuth2SuccessHandler successHandler,
                             OAuth2LoginFailureHandler failureHandler,
                             CookieOAuth2AuthorizationRequestRepository authRequestRepository) {
        this.successHandler = successHandler;
        this.failureHandler = failureHandler;
        this.authRequestRepository = authRequestRepository;
    }

    @Override
    public void customize(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers(
                                "/oauth2/authorization/**",
                                "/login/oauth2/code/**"
                        ).permitAll()
                )
                .oauth2Login(oauth2 -> oauth2
                        .authorizationEndpoint(authorization -> authorization
                                .authorizationRequestRepository(authRequestRepository)
                        )
                        .successHandler(successHandler)
                        .failureHandler(failureHandler)
                );

        log.info("OAuth2 login enabled via auth-oauth2 module. "
                + "Endpoints: /oauth2/authorization/*, /login/oauth2/code/*");
    }
}
