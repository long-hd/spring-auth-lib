package com.hdl.authutils.oauth2.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Configuration properties for auth-oauth2 module.
 */
@Data
@ConfigurationProperties(prefix = "auth.oauth2")
public class AuthOAuth2Properties {

    /**
     * FE callback URL after OAuth2 login success.
     * Lib appends ?token=xxx&expires_at=xxx to this URL.
     * <p>
     * REQUIRED when auth-oauth2 module is on classpath.
     * Example: http://localhost:5173/oauth/callback
     */
    private String redirectUrl;
}
