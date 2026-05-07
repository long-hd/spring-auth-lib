package com.hdl.authutils.ldap.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Configuration properties for auth-ldap module.
 *
 * <p>Example for Active Directory:
 * <pre>
 * auth:
 *   ldap:
 *     url: ldap://ldap.company.com:3268
 *     username: admin
 *     password: secret
 *     base-dn: dc=company,dc=com
 *     user-search-filter: "(&amp;(objectClass=person)(sAMAccountName={0}))"
 *     dn-attribute: distinguishedName
 *     return-attributes: [displayName, mail, memberOf]
 * </pre>
 *
 * <p>Example for OpenLDAP:
 * <pre>
 * auth:
 *   ldap:
 *     url: ldap://ldap.company.com:389
 *     username: cn=admin,dc=company,dc=com
 *     password: secret
 *     base-dn: dc=company,dc=com
 *     user-search-filter: "(&amp;(objectClass=inetOrgPerson)(uid={0}))"
 *     dn-attribute: ""
 *     return-attributes: [cn, mail]
 * </pre>
 */
@Data
@ConfigurationProperties(prefix = "auth.ldap")
public class LdapProperties {

    /** LDAP server URL. Example: ldap://ldap.company.com:3268 */
    private String url;

    /**
     * Bind username for LDAP connection (admin account).
     * Active Directory: plain name ("admin") or UPN ("admin@company.com").
     * OpenLDAP: full DN ("cn=admin,dc=company,dc=com").
     */
    private String username;

    /** Bind password for LDAP connection. */
    private String password;

    /** Base DN for user search. Example: dc=company,dc=com */
    private String baseDn;

    /**
     * LDAP search filter. {0} is replaced with the login username.
     * Default: (&(objectClass=person)(sAMAccountName={0})) — Active Directory.
     * OpenLDAP example: (&(objectClass=inetOrgPerson)(uid={0}))
     */
    private String userSearchFilter = "(&(objectClass=person)(sAMAccountName={0}))";

    /**
     * LDAP attribute containing the user's full Distinguished Name.
     * Used for bind authentication (step 2: bind with DN + password).
     * <p>
     * Active Directory: "distinguishedName" (AD stores DN as an explicit attribute).
     * OpenLDAP: leave empty — the entry's own DN is used instead.
     */
    private String dnAttribute = "distinguishedName";

    /**
     * Attributes to return from LDAP search.
     * Available in LdapAuthResult.attributes() after successful authentication.
     */
    private String[] returnAttributes = {"displayName", "mail", "memberOf"};

    /** LDAP connect timeout in milliseconds. Default: 5000. */
    private int connectTimeout = 5000;

    /** LDAP read timeout in milliseconds. Default: 5000. */
    private int readTimeout = 5000;
}
