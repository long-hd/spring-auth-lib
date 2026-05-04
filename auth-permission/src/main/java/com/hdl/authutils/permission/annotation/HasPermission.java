package com.hdl.authutils.permission.annotation;

import java.lang.annotation.*;

/**
 * Marks a method or class as requiring a specific permission.
 * <p>
 * Permission check is done via SecurityContext.authorities — zero DB calls.
 * Permissions are resolved once by TokenAuthenticationFilter at request start.
 * <p>
 * Usage:
 * <pre>
 * {@literal @}PostMapping
 * {@literal @}HasPermission(module = "SHIPMENT", action = "CREATE")
 * public ResponseEntity create(...) { ... }
 * </pre>
 * <p>
 * Use with constants for type safety:
 * <pre>
 * {@literal @}HasPermission(module = ShipmentPermissions.MODULE, action = ShipmentPermissions.CREATE)
 * </pre>
 */
@Target({ElementType.METHOD, ElementType.TYPE})
@Retention(RetentionPolicy.RUNTIME)
@Documented
public @interface HasPermission {
    String module();
    String action();
}
