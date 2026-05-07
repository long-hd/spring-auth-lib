package com.hdl.authutils.ldap.service;

import com.hdl.authutils.ldap.config.LdapProperties;
import com.hdl.authutils.ldap.model.LdapAuthResult;
import com.hdl.authutils.ldap.model.LdapFailReason;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.ldap.core.AttributesMapper;
import org.springframework.ldap.core.LdapTemplate;
import org.springframework.ldap.query.LdapQueryBuilder;

import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.DirContext;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * LDAP authentication service.
 * <p>
 * Three-step authentication (proven with Active Directory):
 * <ol>
 *   <li>Bind to LDAP with admin account (configured credentials)</li>
 *   <li>Search for user using configured filter → get DN + attributes</li>
 *   <li>Bind with user's DN + password → verify credentials</li>
 * </ol>
 * <p>
 * Does NOT use {@code ldapTemplate.authenticate()} — explicit flow is more
 * reliable with Active Directory and easier to debug.
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
            // Step 1: Search for user (bound with admin credentials from config)
            String filter = properties.getUserSearchFilter().replace("{0}", escapeFilter(username));

            List<SearchEntry> results = ldapTemplate.search(
                    LdapQueryBuilder.query()
                            .base(properties.getBaseDn())
                            .attributes(getAllRequestedAttributes())
                            .filter(filter),
                    new SearchEntryMapper()
            );

            if (results.isEmpty()) {
                log.debug("LDAP user not found: {}", username);
                return LdapAuthResult.failure(LdapFailReason.USER_NOT_FOUND);
            }

            if (results.size() > 1) {
                log.warn("LDAP found {} users for: {}", results.size(), username);
                return LdapAuthResult.failure(LdapFailReason.MULTIPLE_MATCHES);
            }

            SearchEntry entry = results.getFirst();

            // Step 2: Resolve the DN for bind authentication
            String bindDn = resolveBindDn(entry);
            if (bindDn == null || bindDn.isBlank()) {
                log.warn("LDAP could not resolve DN for user: {}", username);
                return LdapAuthResult.failure(LdapFailReason.USER_NOT_FOUND);
            }

            // Step 3: Bind with user DN + password to verify credentials
            if (!bindAuthenticate(bindDn, password)) {
                log.debug("LDAP invalid credentials for: {}", username);
                return LdapAuthResult.failure(LdapFailReason.INVALID_CREDENTIALS);
            }

            log.debug("LDAP authentication success for: {}", username);

            // Remove dn-attribute from returned attributes (internal, not useful for project)
            Map<String, Object> cleanAttributes = new LinkedHashMap<>(entry.attributes());
            String dnAttr = properties.getDnAttribute();
            if (dnAttr != null && !dnAttr.isBlank()) {
                cleanAttributes.remove(dnAttr);
            }

            return LdapAuthResult.success(cleanAttributes);

        } catch (Exception e) {
            log.error("LDAP error for user {}: {}", username, e.getMessage(), e);
            return LdapAuthResult.failure(LdapFailReason.CONNECTION_ERROR);
        }
    }

    // ── Private helpers ─────────────────────────────────────

    /**
     * Resolve the Distinguished Name to bind with.
     * <p>
     * If dnAttribute is configured (Active Directory): read the attribute value.
     * If dnAttribute is empty (OpenLDAP): use the entry's own DN from search result.
     */
    private String resolveBindDn(SearchEntry entry) {
        String dnAttr = properties.getDnAttribute();
        if (dnAttr != null && !dnAttr.isBlank()) {
            // Active Directory: read distinguishedName attribute
            Object dnValue = entry.attributes().get(dnAttr);
            return dnValue != null ? dnValue.toString() : null;
        }
        // OpenLDAP: use entry DN (set by SearchEntryMapper if available)
        return entry.entryDn();
    }

    /**
     * Bind with user DN + password using a new context.
     * Explicit bind — does not use ldapTemplate.authenticate().
     */
    private boolean bindAuthenticate(String userDn, String password) {
        DirContext ctx = null;
        try {
            ctx = ldapTemplate.getContextSource().getContext(userDn, password);
            return true;
        } catch (Exception e) {
            log.debug("Bind failed for DN {}: {}", userDn, e.getMessage());
            return false;
        } finally {
            if (ctx != null) {
                try {
                    ctx.close();
                } catch (Exception ignored) {
                }
            }
        }
    }

    /**
     * Build the full list of attributes to request.
     * Includes returnAttributes + dnAttribute (needed for bind DN resolution).
     */
    private String[] getAllRequestedAttributes() {
        String[] returnAttrs = properties.getReturnAttributes();
        String dnAttr = properties.getDnAttribute();

        if (dnAttr == null || dnAttr.isBlank()) {
            return returnAttrs;
        }

        // Check if dnAttribute is already in returnAttributes
        for (String attr : returnAttrs) {
            if (attr.equalsIgnoreCase(dnAttr)) {
                return returnAttrs;
            }
        }

        // Add dnAttribute to the request
        String[] allAttrs = new String[returnAttrs.length + 1];
        System.arraycopy(returnAttrs, 0, allAttrs, 0, returnAttrs.length);
        allAttrs[returnAttrs.length] = dnAttr;
        return allAttrs;
    }

    /**
     * Escape special characters in LDAP filter values to prevent injection.
     */
    private static String escapeFilter(String value) {
        if (value == null) return "";
        StringBuilder sb = new StringBuilder(value.length());
        for (char c : value.toCharArray()) {
            switch (c) {
                case '\\' -> sb.append("\\5c");
                case '*' -> sb.append("\\2a");
                case '(' -> sb.append("\\28");
                case ')' -> sb.append("\\29");
                case '\0' -> sb.append("\\00");
                default -> sb.append(c);
            }
        }
        return sb.toString();
    }

    // ── Internal types ──────────────────────────────────────

    /**
     * Internal record holding search result: entry DN + attributes.
     */
    record SearchEntry(String entryDn, Map<String, Object> attributes) {
    }

    /**
     * Maps LDAP search result to SearchEntry.
     * Extracts all attributes into a Map (single-value → Object, multi-value → List).
     */
    private static class SearchEntryMapper implements AttributesMapper<SearchEntry> {
        @Override
        public SearchEntry mapFromAttributes(Attributes attrs) throws NamingException {
            Map<String, Object> map = new LinkedHashMap<>();
            NamingEnumeration<? extends Attribute> all = attrs.getAll();
            while (all.hasMore()) {
                Attribute attr = all.next();
                if (attr.size() == 1) {
                    map.put(attr.getID(), attr.get());
                } else {
                    // Multi-value attribute (e.g., memberOf)
                    List<Object> values = new ArrayList<>();
                    NamingEnumeration<?> valEnum = attr.getAll();
                    while (valEnum.hasMore()) {
                        values.add(valEnum.next());
                    }
                    map.put(attr.getID(), values);
                }
            }
            // Entry DN is not available through AttributesMapper directly.
            // It's available if using ContextMapper or NameClassPairMapper.
            // For now, we rely on dnAttribute for AD.
            return new SearchEntry(null, map);
        }
    }
}
