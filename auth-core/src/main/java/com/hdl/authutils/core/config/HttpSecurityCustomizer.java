package com.hdl.authutils.core.config;

import org.springframework.security.config.annotation.web.builders.HttpSecurity;

/**
 * Callback to customize the default SecurityFilterChain provided by auth-lib.
 * <p>
 * Each auth module can provide a bean implementing this interface to add
 * its own config (e.g., auth-oauth2 adds .oauth2Login()).
 * <p>
 * Only used when project does NOT define its own SecurityFilterChain bean.
 * If project defines SecurityFilterChain, these customizers are ignored.
 */
@FunctionalInterface
public interface HttpSecurityCustomizer {

    void customize(HttpSecurity http) throws Exception;
}
