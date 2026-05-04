package com.hdl.authutils.core.service;

import com.hdl.authutils.core.exception.AuthException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;

import java.util.*;
import java.util.stream.Collectors;

/**
 * The ONLY way to access current authenticated user info.
 * Reads from SecurityContext — no ThreadLocal, no static methods.
 * <p>
 * Inject this bean wherever you need user info:
 * <pre>
 * {@literal @}RequiredArgsConstructor
 * public class MyService {
 *     private final CurrentUserProvider currentUser;
 *
 *     void doSomething() {
 *         Long userId = currentUser.getUserId();
 *         String name = currentUser.getUsername();
 *     }
 * }
 * </pre>
 */
public class CurrentUserProvider {

    public Long getUserId() {
        return (Long) getRequiredAuthentication().getPrincipal();
    }

    public String getUsername() {
        return getDetail("username", String.class).orElse(null);
    }

    public String getDisplayName() {
        return getDetail("displayName", String.class).orElse(null);
    }

    @SuppressWarnings("unchecked")
    public Set<String> getRoles() {
        return getDetail("roles", Set.class).orElse(Set.of());
    }

    /**
     * Get a custom claim from JWT additionalClaims.
     * <pre>
     * Long companyId = currentUser.getClaim("companyId", Long.class).orElse(null);
     * </pre>
     */
    @SuppressWarnings("unchecked")
    public <T> Optional<T> getClaim(String key, Class<T> type) {
        return getDetail(key, type);
    }

    /**
     * Shortcut for getClaim("companyId", Long.class).
     */
    public Optional<Long> getCompanyId() {
        // JWT numeric values may deserialize as Integer
        return getDetail("companyId", Number.class).map(Number::longValue);
    }

    /**
     * Check if current user has a specific permission.
     * Permission format: "MODULE:ACTION" (e.g., "DRIVER:CREATE")
     */
    public boolean hasPermission(String permission) {
        Authentication auth = getAuthentication();
        if (auth == null) return false;
        return auth.getAuthorities().stream()
                .anyMatch(a -> a.getAuthority().equals(permission));
    }

    /**
     * Check if current user has a specific module:action permission.
     */
    public boolean hasPermission(String module, String action) {
        return hasPermission(module + ":" + action);
    }

    /**
     * Check if current user has ANY of the given permissions.
     */
    public boolean hasAnyPermission(String... permissions) {
        Authentication auth = getAuthentication();
        if (auth == null) return false;
        Set<String> grantedSet = auth.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.toSet());
        for (String p : permissions) {
            if (grantedSet.contains(p)) return true;
        }
        return false;
    }

    /**
     * Check if current user has a specific role.
     */
    public boolean hasRole(String role) {
        return getRoles().contains(role);
    }

    /**
     * Get the raw Authentication object (escape hatch).
     */
    public Authentication getAuthentication() {
        return SecurityContextHolder.getContext().getAuthentication();
    }

    public boolean isAuthenticated() {
        Authentication auth = getAuthentication();
        return auth != null && auth.isAuthenticated()
                && auth.getPrincipal() instanceof Long;
    }

    // ── Private helpers ─────────────────────────────────────

    private Authentication getRequiredAuthentication() {
        Authentication auth = getAuthentication();
        if (auth == null || !auth.isAuthenticated()
                || !(auth.getPrincipal() instanceof Long)) {
            throw new AuthException("No authenticated user in SecurityContext");
        }
        return auth;
    }

    @SuppressWarnings("unchecked")
    private <T> Optional<T> getDetail(String key, Class<T> type) {
        Authentication auth = getAuthentication();
        if (auth == null || !(auth.getDetails() instanceof Map)) {
            return Optional.empty();
        }
        Map<String, Object> details = (Map<String, Object>) auth.getDetails();
        Object value = details.get(key);
        if (value == null) return Optional.empty();
        if (type.isInstance(value)) {
            return Optional.of(type.cast(value));
        }
        // Handle numeric type conversions (JWT deserializes numbers as Integer)
        if (Number.class.isAssignableFrom(type) && value instanceof Number) {
            return Optional.of(type.cast(value));
        }
        return Optional.empty();
    }
}
