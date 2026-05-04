package com.hdl.authutils.permission.resolver;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.hdl.authutils.core.service.PermissionResolver;
import com.hdl.authutils.permission.config.PermissionProperties;
import com.hdl.authutils.permission.port.RolePermissionPort;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Collection;
import java.util.Collections;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Permission resolver backed by Caffeine cache.
 * <p>
 * Caches permissions per role name. Each role's permissions are loaded once
 * via RolePermissionPort and cached for configurable TTL.
 * <p>
 * This replaces NoOpPermissionResolver when auth-permission module is on classpath.
 */
public class CachedPermissionResolver implements PermissionResolver {

    private static final Logger log = LoggerFactory.getLogger(CachedPermissionResolver.class);

    private final RolePermissionPort rolePermissionPort;
    private final Cache<String, Set<String>> cache;

    public CachedPermissionResolver(RolePermissionPort rolePermissionPort,
                                     PermissionProperties properties) {
        this.rolePermissionPort = rolePermissionPort;
        this.cache = Caffeine.newBuilder()
                .maximumSize(properties.getCacheMaxSize())
                .expireAfterWrite(properties.getCacheTtl())
                .build();
        log.info("CachedPermissionResolver initialized: cacheTtl={}, maxSize={}",
                properties.getCacheTtl(), properties.getCacheMaxSize());
    }

    @Override
    public Set<String> resolve(Collection<String> roleNames) {
        if (roleNames == null || roleNames.isEmpty()) {
            return Collections.emptySet();
        }
        return roleNames.stream()
                .flatMap(roleName -> getPermissions(roleName).stream())
                .collect(Collectors.toUnmodifiableSet());
    }

    /**
     * Invalidate cache for a specific role.
     * Call when admin changes role-permission mapping.
     */
    public void evict(String roleName) {
        cache.invalidate(roleName);
        log.debug("Evicted permission cache for role: {}", roleName);
    }

    /**
     * Invalidate entire cache.
     * Call when bulk permission changes are made.
     */
    public void evictAll() {
        cache.invalidateAll();
        log.debug("Evicted entire permission cache");
    }

    private Set<String> getPermissions(String roleName) {
        return cache.get(roleName, this::loadFromPort);
    }

    private Set<String> loadFromPort(String roleName) {
        log.debug("Loading permissions from DB for role: {}", roleName);
        Set<String> permissions = rolePermissionPort.loadPermissions(roleName);
        return permissions != null ? Set.copyOf(permissions) : Set.of();
    }
}
