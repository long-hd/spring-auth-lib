package com.hdl.authutils.core.service;

import com.hdl.authutils.core.model.RefreshToken;

import java.util.List;
import java.util.Optional;

/**
 * Storage for refresh tokens.
 * <p>
 * Default: InMemoryRefreshTokenStore (dev/testing only).
 * Production: project implements DB-backed or Redis-backed store.
 */
public interface RefreshTokenStore {

    void save(RefreshToken token);

    Optional<RefreshToken> findByToken(String tokenValue);

    void revokeByToken(String tokenValue);

    void revokeAllByUserId(Long userId);

    /** For token family strategy: revoke all tokens in a family. */
    void revokeAllByFamily(String familyId);

    /** For token family strategy: find all tokens in a family. */
    List<RefreshToken> findByFamily(String familyId);
}
