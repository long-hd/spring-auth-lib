package com.hdl.authutils.core.service;

import java.util.Collection;
import java.util.Set;

/**
 * Resolves role names to permission strings.
 * <p>
 * auth-core provides NoOpPermissionResolver (returns empty set).
 * auth-permission provides CachedPermissionResolver (DB + cache).
 * <p>
 * Used by TokenAuthenticationFilter to populate SecurityContext.authorities.
 */
public interface PermissionResolver {

    /**
     * Resolve a collection of role names to a set of permission strings.
     * Permission format: "MODULE:ACTION" (e.g., "DRIVER:CREATE", "SHIPMENT:VIEW_ALL")
     *
     * @param roleNames role names from JWT claims
     * @return permission strings to set as GrantedAuthority
     */
    Set<String> resolve(Collection<String> roleNames);
}
