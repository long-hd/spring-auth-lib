package com.hdl.authutils.permission.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.time.Duration;

/**
 * Configuration properties for auth-permission module.
 */
@Data
@ConfigurationProperties(prefix = "auth.permission")
public class PermissionProperties {

    /** Cache TTL for role permissions. Default: 30 minutes. */
    private Duration cacheTtl = Duration.ofMinutes(30);

    /** Maximum cache entries. Default: 1000. */
    private long cacheMaxSize = 1000;
}
