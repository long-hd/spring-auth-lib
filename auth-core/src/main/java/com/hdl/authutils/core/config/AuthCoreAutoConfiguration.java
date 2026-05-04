package com.hdl.authutils.core.config;

import com.hdl.authutils.core.filter.TokenAuthenticationFilter;
import com.hdl.authutils.core.service.*;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.core.env.Environment;

/**
 * Auto-configuration for auth-core module.
 * <p>
 * All beans use {@code @ConditionalOnMissingBean} so projects can override
 * any bean by defining their own.
 */
@AutoConfiguration
@EnableConfigurationProperties(AuthProperties.class)
public class AuthCoreAutoConfiguration {

    @Bean
    AuthPropertiesValidator authPropertiesValidator(AuthProperties properties) {
        return new AuthPropertiesValidator(properties);
    }

    @Bean
    @ConditionalOnMissingBean
    public RefreshTokenStore refreshTokenStore(Environment environment) {
        return new InMemoryRefreshTokenStore(environment);
    }

    @Bean
    @ConditionalOnMissingBean
    public PermissionResolver permissionResolver() {
        return new NoOpPermissionResolver();
    }

    @Bean
    @ConditionalOnMissingBean
    public TokenService tokenService(AuthProperties properties,
                                     RefreshTokenStore refreshTokenStore,
                                     // Optional: TokenClaimsEnricher may not be provided
                                     org.springframework.beans.factory.ObjectProvider<TokenClaimsEnricher> enricherProvider) {
        return new DefaultTokenService(properties, refreshTokenStore, enricherProvider.getIfAvailable());
    }

    @Bean
    @ConditionalOnMissingBean
    public CurrentUserProvider currentUserProvider() {
        return new CurrentUserProvider();
    }

    @Bean
    @ConditionalOnMissingBean
    public RefreshTokenCookieHelper refreshTokenCookieHelper(AuthProperties properties) {
        return new RefreshTokenCookieHelper(properties);
    }

    @Bean
    @ConditionalOnMissingBean
    public TokenAuthenticationFilter tokenAuthenticationFilter(
            TokenService tokenService,
            PermissionResolver permissionResolver,
            AuthProperties properties) {
        return new TokenAuthenticationFilter(tokenService, permissionResolver, properties);
    }
}
