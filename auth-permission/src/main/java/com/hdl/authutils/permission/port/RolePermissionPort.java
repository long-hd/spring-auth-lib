package com.hdl.authutils.permission.port;

import java.util.Set;

/**
 * Port for loading permissions from persistence.
 * Project MUST implement this interface.
 * <p>
 * Implementation example:
 * <pre>
 * {@literal @}Component
 * public class RolePermissionAdapter implements RolePermissionPort {
 *     private final PermissionRepository repo;
 *
 *     {@literal @}Override
 *     public Set&lt;String&gt; loadPermissions(String roleName) {
 *         return repo.findByRoleName(roleName).stream()
 *             .map(p -> p.getModule() + ":" + p.getAction())
 *             .collect(Collectors.toUnmodifiableSet());
 *     }
 * }
 * </pre>
 */
public interface RolePermissionPort {

    /**
     * Load permission strings for a single role.
     *
     * @param roleName the role name (e.g., "ADMIN", "OPERATOR")
     * @return permission strings in format "MODULE:ACTION"
     *         (e.g., {"DRIVER:CREATE", "SHIPMENT:VIEW_ALL"})
     */
    Set<String> loadPermissions(String roleName);
}
