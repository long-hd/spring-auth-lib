package com.hdl.authutils.core.config;

import com.hdl.authutils.core.filter.TokenAuthenticationFilter;
import com.hdl.authutils.core.service.*;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.core.env.Environment;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

/**
 * Auto-configuration for auth-core module.
 * <p>
 * All beans use {@code @ConditionalOnMissingBean} so projects can override
 * any bean by defining their own.
 * <p>
 * Imports {@link DefaultSecurityFilterChainConfig} which provides a default
 * SecurityFilterChain. If project defines its own SecurityFilterChain bean,
 * the default is automatically skipped.
 */
@AutoConfiguration
@EnableConfigurationProperties(AuthProperties.class)
@Import(DefaultSecurityFilterChainConfig.class)
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

    /**
     * Default PasswordEncoder using BCrypt (strength 10).
     * Project can override by defining its own PasswordEncoder bean
     * (e.g., Argon2, SCrypt, DelegatingPasswordEncoder).
     */
    @Bean
    @ConditionalOnMissingBean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder(10);
    }
}
