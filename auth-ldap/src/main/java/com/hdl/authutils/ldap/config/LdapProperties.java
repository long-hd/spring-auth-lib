package com.hdl.authutils.ldap.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Configuration properties for auth-ldap module.
 */
@Data
@ConfigurationProperties(prefix = "auth.ldap")
public class LdapProperties {

    /** LDAP server URL. Example: ldap://ldap.company.com:389 */
    private String url;

    /** Bind DN for LDAP connection. Example: cn=admin,dc=example,dc=com */
    private String username;

    /** Bind password for LDAP connection. */
    private String password;

    /** Base DN for user search. Example: dc=example,dc=com */
    private String baseDn;

    /**
     * LDAP filter to find users. {0} is replaced with the login username.
     * Default: (sAMAccountName={0}) — Active Directory.
     * For OpenLDAP: (uid={0})
     */
    private String userSearchFilter = "(sAMAccountName={0})";

    /** Attributes to return from LDAP search. */
    private String[] returnAttributes = {"displayName", "mail", "memberOf"};
}
