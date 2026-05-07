package com.hdl.authutils.permission.config;

import com.hdl.authutils.core.config.AuthCoreAutoConfiguration;
import com.hdl.authutils.core.service.PermissionResolver;
import com.hdl.authutils.permission.aspect.PermissionAspect;
import com.hdl.authutils.permission.port.RolePermissionPort;
import com.hdl.authutils.permission.resolver.CachedPermissionResolver;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;

/**
 * Auto-configuration for auth-permission module.
 * <p>
 * Runs after AuthCoreAutoConfiguration.
 * CachedPermissionResolver overrides NoOpPermissionResolver from auth-core
 * via {@code @Primary} — Spring injects the primary bean when multiple
 * PermissionResolver beans exist.
 * <p>
 * Requires project to provide a {@link RolePermissionPort} bean.
 */
@AutoConfiguration(after = AuthCoreAutoConfiguration.class)
@EnableConfigurationProperties(PermissionProperties.class)
public class AuthPermissionAutoConfiguration {

    /**
     * CachedPermissionResolver overrides NoOpPermissionResolver.
     * <p>
     * Uses {@code @Primary} instead of {@code @ConditionalOnMissingBean} because
     * NoOpPermissionResolver is already registered by auth-core auto-config.
     * {@code @Primary} ensures Spring injects this bean for all PermissionResolver
     * injection points.
     * <p>
     * Only activates when project provides a {@link RolePermissionPort} bean.
     */
    @Bean
    @Primary
    @ConditionalOnBean(RolePermissionPort.class)
    public PermissionResolver cachedPermissionResolver(
            RolePermissionPort rolePermissionPort,
            PermissionProperties properties) {
        return new CachedPermissionResolver(rolePermissionPort, properties);
    }

    @Bean
    @ConditionalOnMissingBean
    public PermissionAspect permissionAspect() {
        return new PermissionAspect();
    }
}
