package com.hdl.authutils.core.service;

import com.hdl.authutils.core.model.RefreshToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.env.Environment;

import jakarta.annotation.PostConstruct;
import jakarta.annotation.PreDestroy;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.*;

/**
 * In-memory RefreshTokenStore using ConcurrentHashMap.
 * Suitable for development and testing only.
 * <p>
 * Logs WARNING when production profile is detected.
 * Automatically cleans up expired tokens every 5 minutes.
 */
public class InMemoryRefreshTokenStore implements RefreshTokenStore {

    private static final Logger log = LoggerFactory.getLogger(InMemoryRefreshTokenStore.class);

    private final ConcurrentMap<String, RefreshToken> store = new ConcurrentHashMap<>();
    private final ScheduledExecutorService scheduler = Executors.newSingleThreadScheduledExecutor(r -> {
        Thread t = new Thread(r, "auth-refresh-cleanup");
        t.setDaemon(true);
        return t;
    });
    private final Environment environment;

    public InMemoryRefreshTokenStore(Environment environment) {
        this.environment = environment;
    }

    @PostConstruct
    void init() {
        List<String> activeProfiles = List.of(environment.getActiveProfiles());
        if (activeProfiles.contains("prod") || activeProfiles.contains("production")
                || activeProfiles.contains("staging")) {
            log.warn("!!! InMemoryRefreshTokenStore is active in '{}' profile. "
                            + "This is NOT suitable for production. "
                            + "Implement RefreshTokenStore with DB or Redis backing. !!!",
                    activeProfiles);
        }

        scheduler.scheduleAtFixedRate(this::cleanup, 5, 5, TimeUnit.MINUTES);
    }

    @PreDestroy
    void shutdown() {
        scheduler.shutdownNow();
    }

    @Override
    public void save(RefreshToken token) {
        store.put(token.tokenValue(), token);
    }

    @Override
    public Optional<RefreshToken> findByToken(String tokenValue) {
        return Optional.ofNullable(store.get(tokenValue));
    }

    @Override
    public void revokeByToken(String tokenValue) {
        store.computeIfPresent(tokenValue, (k, existing) -> withRevoked(existing));
    }

    @Override
    public void revokeAllByUserId(Long userId) {
        store.replaceAll((k, existing) -> {
            if (existing.userId().equals(userId) && !existing.revoked()) {
                return withRevoked(existing);
            }
            return existing;
        });
    }

    @Override
    public void revokeAllByFamily(String familyId) {
        if (familyId == null) return;
        store.replaceAll((k, existing) -> {
            if (familyId.equals(existing.familyId()) && !existing.revoked()) {
                return withRevoked(existing);
            }
            return existing;
        });
    }

    @Override
    public List<RefreshToken> findByFamily(String familyId) {
        if (familyId == null) return List.of();
        return store.values().stream()
                .filter(t -> familyId.equals(t.familyId()))
                .toList();
    }

    /**
     * Create a revoked copy of a refresh token, preserving all fields.
     */
    private RefreshToken withRevoked(RefreshToken existing) {
        return RefreshToken.builder()
                .tokenValue(existing.tokenValue())
                .userId(existing.userId())
                .familyId(existing.familyId())
                .expiresAt(existing.expiresAt())
                .createdAt(existing.createdAt())
                .revoked(true)
                .username(existing.username())
                .displayName(existing.displayName())
                .roles(existing.roles())
                .additionalClaims(existing.additionalClaims())
                .build();
    }

    private void cleanup() {
        int removed = 0;
        Iterator<Map.Entry<String, RefreshToken>> it = store.entrySet().iterator();
        while (it.hasNext()) {
            RefreshToken token = it.next().getValue();
            if (token.isExpired() || token.revoked()) {
                it.remove();
                removed++;
            }
        }
        if (removed > 0) {
            log.debug("Cleaned up {} expired/revoked refresh tokens, {} remaining", removed, store.size());
        }
    }
}
