package com.hdl.authutils.core.model;

import lombok.Builder;

import java.util.Map;
import java.util.Set;

/**
 * Request to generate a token pair.
 * Built by project's login flow, passed to TokenService.
 */
@Builder
public record TokenRequest(
        Long userId,
        String username,
        String displayName,
        Set<String> roles,
        Map<String, Object> additionalClaims
) {
        public TokenRequest {
                if(roles==null) roles = Set.of();
                if(additionalClaims==null) additionalClaims = Map.of();
        }
}
