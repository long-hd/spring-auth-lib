package com.hdl.authutils.ldap.model;

/**
 * Reasons an LDAP authentication can fail.
 */
public enum LdapFailReason {
    USER_NOT_FOUND,
    INVALID_CREDENTIALS,
    MULTIPLE_MATCHES,
    CONNECTION_ERROR
}
