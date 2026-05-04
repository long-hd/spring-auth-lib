package com.hdl.authutils.ldap.model;

import java.util.Map;

/**
 * Result of LDAP authentication attempt.
 */
public record LdapAuthResult(
        boolean success,
        LdapFailReason failReason,          // null if success
        Map<String, Object> attributes      // LDAP attributes if success, empty if failed
) {

    public static LdapAuthResult success(Map<String, Object> attributes) {
        return new LdapAuthResult(true, null, attributes);
    }

    public static LdapAuthResult failure(LdapFailReason reason) {
        return new LdapAuthResult(false, reason, Map.of());
    }
}
