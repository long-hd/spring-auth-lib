package com.hdl.authutils.ldap.config;

import com.hdl.authutils.core.config.AuthCoreAutoConfiguration;
import com.hdl.authutils.ldap.service.LdapAuthenticationService;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.ldap.core.LdapTemplate;
import org.springframework.ldap.core.support.LdapContextSource;

/**
 * Auto-configuration for auth-ldap module.
 * <p>
 * Only activates when {@code auth.ldap.url} is configured.
 * Provides LdapContextSource, LdapTemplate, and LdapAuthenticationService.
 */
@AutoConfiguration(after = AuthCoreAutoConfiguration.class)
@EnableConfigurationProperties(LdapProperties.class)
@ConditionalOnProperty(prefix = "auth.ldap", name = "url")
public class AuthLdapAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean
    public LdapContextSource ldapContextSource(LdapProperties properties) {
        LdapContextSource contextSource = new LdapContextSource();
        contextSource.setUrl(properties.getUrl());
        contextSource.setBase(properties.getBaseDn());

        if (properties.getUsername() != null && !properties.getUsername().isBlank()) {
            contextSource.setUserDn(properties.getUsername());
            contextSource.setPassword(properties.getPassword());
        }

        contextSource.afterPropertiesSet();
        return contextSource;
    }

    @Bean
    @ConditionalOnMissingBean
    public LdapTemplate ldapTemplate(LdapContextSource contextSource) {
        return new LdapTemplate(contextSource);
    }

    @Bean
    @ConditionalOnMissingBean
    public LdapAuthenticationService ldapAuthenticationService(
            LdapTemplate ldapTemplate,
            LdapProperties properties) {
        return new LdapAuthenticationService(ldapTemplate, properties);
    }
}
