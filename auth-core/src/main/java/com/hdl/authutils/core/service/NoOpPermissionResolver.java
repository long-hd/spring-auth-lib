package com.hdl.authutils.core.service;

import java.util.Collection;
import java.util.Collections;
import java.util.Set;

/**
 * Default PermissionResolver that returns no permissions.
 * Active when auth-permission module is NOT on classpath.
 * SecurityContext will only contain roles, not permissions.
 */
public class NoOpPermissionResolver implements PermissionResolver {

    @Override
    public Set<String> resolve(Collection<String> roleNames) {
        return Collections.emptySet();
    }
}
