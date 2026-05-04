package com.hdl.authutils.oauth2.config;

import com.hdl.authutils.core.config.AuthCoreAutoConfiguration;
import com.hdl.authutils.oauth2.mapper.DefaultOidcUserInfoMapper;
import com.hdl.authutils.oauth2.mapper.OAuth2UserInfoMapper;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;

/**
 * Auto-configuration for auth-oauth2 module.
 * <p>
 * Provides default OIDC mapper. Project must provide:
 * <ul>
 *   <li>A bean extending {@link com.hdl.authutils.oauth2.handler.BaseOAuth2SuccessHandler}</li>
 *   <li>Optional custom {@link OAuth2UserInfoMapper} beans for non-standard providers</li>
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
}
