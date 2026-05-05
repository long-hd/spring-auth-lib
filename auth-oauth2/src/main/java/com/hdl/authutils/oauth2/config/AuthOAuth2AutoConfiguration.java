package com.hdl.authutils.oauth2.config;

import com.hdl.authutils.core.config.AuthCoreAutoConfiguration;
import com.hdl.authutils.core.config.HttpSecurityCustomizer;
import com.hdl.authutils.oauth2.handler.BaseOAuth2SuccessHandler;
import com.hdl.authutils.oauth2.handler.CookieOAuth2AuthorizationRequestRepository;
import com.hdl.authutils.oauth2.handler.OAuth2LoginFailureHandler;
import com.hdl.authutils.oauth2.mapper.DefaultOidcUserInfoMapper;
import com.hdl.authutils.oauth2.mapper.OAuth2UserInfoMapper;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;

/**
 * Auto-configuration for auth-oauth2 module.
 * <p>
 * Provides:
 * <ul>
 * <li>{@link DefaultOidcUserInfoMapper} — fallback mapper for OIDC
 * providers</li>
 * <li>{@link CookieOAuth2AuthorizationRequestRepository} — stateless OAuth2
 * state storage</li>
 * <li>{@link OAuth2LoginFailureHandler} — redirects to FE with error param</li>
 * <li>{@link OAuth2SecurityCustomizer} — adds .oauth2Login() to default
 * SecurityFilterChain</li>
 * </ul>
 * <p>
 * Project must provide:
 * <ul>
 * <li>A bean extending {@link BaseOAuth2SuccessHandler}</li>
 * <li>Optional custom {@link OAuth2UserInfoMapper} beans for non-standard
 * providers</li>
 * </ul>
 */
@AutoConfiguration(after = AuthCoreAutoConfiguration.class)
@EnableConfigurationProperties(AuthOAuth2Properties.class)
public class AuthOAuth2AutoConfiguration {

    @Bean
    @ConditionalOnMissingBean(DefaultOidcUserInfoMapper.class)
    public DefaultOidcUserInfoMapper defaultOidcUserInfoMapper() {
        return new DefaultOidcUserInfoMapper();
    }

    @Bean
    @ConditionalOnMissingBean
    public CookieOAuth2AuthorizationRequestRepository cookieOAuth2AuthorizationRequestRepository() {
        return new CookieOAuth2AuthorizationRequestRepository();
    }

    @Bean
    @ConditionalOnMissingBean
    public OAuth2LoginFailureHandler oAuth2LoginFailureHandler(AuthOAuth2Properties properties) {
        return new OAuth2LoginFailureHandler(properties);
    }

    /**
     * OAuth2 customizer for the default SecurityFilterChain.
     * Only activates when project provides a BaseOAuth2SuccessHandler bean.
     * If project defines its own SecurityFilterChain, this customizer is ignored
     * (because DefaultSecurityFilterChainConfig is skipped entirely).
     */
    @Bean
    @ConditionalOnBean(BaseOAuth2SuccessHandler.class)
    @ConditionalOnMissingBean(OAuth2SecurityCustomizer.class)
    public HttpSecurityCustomizer oAuth2SecurityCustomizer(
            BaseOAuth2SuccessHandler successHandler,
            OAuth2LoginFailureHandler failureHandler,
            CookieOAuth2AuthorizationRequestRepository authRequestRepository) {
        return new OAuth2SecurityCustomizer(successHandler, failureHandler, authRequestRepository);
    }
}
