package com.hdl.authutils.ldap.service;

import com.hdl.authutils.ldap.config.LdapProperties;
import com.hdl.authutils.ldap.model.LdapAuthResult;
import com.hdl.authutils.ldap.model.LdapFailReason;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.ldap.core.AttributesMapper;
import org.springframework.ldap.core.LdapTemplate;
import org.springframework.ldap.query.LdapQueryBuilder;
import org.springframework.ldap.support.LdapUtils;

import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * LDAP authentication service.
 * <p>
 * Two-step authentication:
 * <ol>
 *   <li>Search for user DN using admin bind (configured credentials)</li>
 *   <li>Attempt bind with found DN + user password</li>
 * </ol>
 * <p>
 * Usage in project's LoginUseCase:
 * <pre>
 * LdapAuthResult result = ldapAuthService.authenticate(username, password);
 * if (!result.success()) {
 *     throw new AuthException("LDAP: " + result.failReason());
 * }
 * String displayName = (String) result.attributes().get("displayName");
 * </pre>
 */
public class LdapAuthenticationService {

    private static final Logger log = LoggerFactory.getLogger(LdapAuthenticationService.class);

    private final LdapTemplate ldapTemplate;
    private final LdapProperties properties;

    public LdapAuthenticationService(LdapTemplate ldapTemplate, LdapProperties properties) {
        this.ldapTemplate = ldapTemplate;
        this.properties = properties;
    }

    /**
     * Authenticate user against LDAP.
     *
     * @param username the login username (e.g., sAMAccountName or uid)
     * @param password the user's password
     * @return result with success/failure and LDAP attributes
     */
    public LdapAuthResult authenticate(String username, String password) {
        try {
            // Step 1: Search for user DN
            String filter = properties.getUserSearchFilter().replace("{0}", username);

            List<UserSearchResult> results = ldapTemplate.search(
                    LdapQueryBuilder.query()
                            .base(properties.getBaseDn())
                            .attributes(properties.getReturnAttributes())
                            .filter(filter),
                    new UserAttributesMapper()
            );

            if (results.isEmpty()) {
                log.debug("LDAP user not found: {}", username);
                return LdapAuthResult.failure(LdapFailReason.USER_NOT_FOUND);
            }

            if (results.size() > 1) {
                log.warn("LDAP found multiple users for: {}", username);
                return LdapAuthResult.failure(LdapFailReason.MULTIPLE_MATCHES);
            }

            UserSearchResult userResult = results.getFirst();

            // Step 2: Bind with user DN + password to verify credentials
            boolean authenticated = ldapTemplate.authenticate(
                    LdapUtils.emptyLdapName(),
                    filter,
                    password
            );

            if (!authenticated) {
                log.debug("LDAP invalid credentials for: {}", username);
                return LdapAuthResult.failure(LdapFailReason.INVALID_CREDENTIALS);
            }

            log.debug("LDAP authentication success for: {}", username);
            return LdapAuthResult.success(userResult.attributes());

        } catch (Exception e) {
            log.error("LDAP connection error: {}", e.getMessage(), e);
            return LdapAuthResult.failure(LdapFailReason.CONNECTION_ERROR);
        }
    }

    // ── Internal ─────────────────────────────────────

    private record UserSearchResult(Map<String, Object> attributes) {
    }

    private static class UserAttributesMapper implements AttributesMapper<UserSearchResult> {
        @Override
        public UserSearchResult mapFromAttributes(Attributes attrs) throws NamingException {
            Map<String, Object> map = new LinkedHashMap<>();
            NamingEnumeration<? extends Attribute> all = attrs.getAll();
            while (all.hasMore()) {
                Attribute attr = all.next();
                if (attr.size() == 1) {
                    map.put(attr.getID(), attr.get());
                } else {
                    // Multi-value attribute (e.g., memberOf)
                    List<Object> values = new java.util.ArrayList<>();
                    NamingEnumeration<?> valEnum = attr.getAll();
                    while (valEnum.hasMore()) {
                        values.add(valEnum.next());
                    }
                    map.put(attr.getID(), values);
                }
            }
            return new UserSearchResult(map);
        }
    }
}
