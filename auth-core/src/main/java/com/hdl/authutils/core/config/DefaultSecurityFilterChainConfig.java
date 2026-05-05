package com.hdl.authutils.core.config;

import com.hdl.authutils.core.filter.TokenAuthenticationFilter;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.List;

/**
 * Default SecurityFilterChain provided by auth-lib.
 * <p>
 * Beans are conditional — when project defines its own SecurityFilterChain,
 * the default beans are skipped (via {@code @ConditionalOnMissingBean}).
 * <p>
 * Other auth modules (auth-oauth2, auth-ldap) can extend this default via
 * {@link HttpSecurityCustomizer} beans — no need for project to write SecurityConfig
 * just to enable OAuth2.
 * <p>
 * Default behavior:
 * <ul>
 *   <li>CSRF disabled (stateless JWT API)</li>
 *   <li>CORS from config (auth.security.cors.*)</li>
 *   <li>Stateless session</li>
 *   <li>White list from config (auth.security.white-list)</li>
 *   <li>All other requests require authentication</li>
 *   <li>TokenAuthenticationFilter before UsernamePasswordAuthenticationFilter</li>
 *   <li>JSON error responses for 401/403</li>
 * </ul>
 */
@Configuration(proxyBeanMethods = false)
class DefaultSecurityFilterChainConfig {

    private static final Logger log = LoggerFactory.getLogger(DefaultSecurityFilterChainConfig.class);

    /**
     * Default SecurityFilterChain.
     * Skipped when project defines its own SecurityFilterChain bean.
     */
    @Bean
    @ConditionalOnMissingBean(SecurityFilterChain.class)
    SecurityFilterChain defaultSecurityFilterChain(
            HttpSecurity http,
            TokenAuthenticationFilter tokenAuthFilter,
            AuthProperties properties,
            List<HttpSecurityCustomizer> customizers) throws Exception {

        var security = properties.getSecurity();

        http
                .csrf(AbstractHttpConfigurer::disable)
                .cors(Customizer.withDefaults())
                .sessionManagement(session ->
                        session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(auth -> {
                    security.getWhiteList().forEach(
                            pattern -> auth.requestMatchers(pattern).permitAll()
                    );
                    auth.anyRequest().authenticated();
                })
                .addFilterBefore(tokenAuthFilter, UsernamePasswordAuthenticationFilter.class)
                .exceptionHandling(ex -> ex
                        .authenticationEntryPoint((req, res, authEx) -> {
                            res.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                            res.setContentType("application/json");
                            res.getWriter().write(
                                    "{\"error\":\"UNAUTHORIZED\",\"message\":\"Authentication required\"}");
                        })
                        .accessDeniedHandler((req, res, accessEx) -> {
                            res.setStatus(HttpServletResponse.SC_FORBIDDEN);
                            res.setContentType("application/json");
                            res.getWriter().write(
                                    "{\"error\":\"FORBIDDEN\",\"message\":\"Insufficient permissions\"}");
                        })
                );

        // Apply customizers from other modules (e.g., auth-oauth2 adds .oauth2Login())
        for (HttpSecurityCustomizer customizer : customizers) {
            customizer.customize(http);
        }

        log.info("Auth-lib default SecurityFilterChain active. "
                        + "White list: {}. To override, define your own SecurityFilterChain bean.",
                security.getWhiteList());

        return http.build();
    }

    @Bean
    @ConditionalOnMissingBean
    CorsConfigurationSource corsConfigurationSource(AuthProperties properties) {
        var corsConfig = properties.getSecurity().getCors();

        CorsConfiguration config = new CorsConfiguration();
        config.setAllowedOriginPatterns(corsConfig.getAllowedOriginPatterns());
        config.setAllowedMethods(corsConfig.getAllowedMethods());
        config.setAllowedHeaders(corsConfig.getAllowedHeaders());
        config.setAllowCredentials(corsConfig.isAllowCredentials());
        config.setMaxAge(corsConfig.getMaxAge());

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", config);
        return source;
    }
}
