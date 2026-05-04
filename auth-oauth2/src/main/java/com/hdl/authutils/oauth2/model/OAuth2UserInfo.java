package com.hdl.authutils.oauth2.model;

import java.util.Map;

/**
 * Standardized user info extracted from OAuth2/OIDC provider response.
 * Produced by {@link com.hdl.authutils.oauth2.mapper.OAuth2UserInfoMapper}.
 */
public record OAuth2UserInfo(
        String email,
        String displayName,
        String avatarUrl,
        String providerUserId,
        String provider,                    // "google", "zalo", "tiktok"
        Map<String, Object> rawAttributes   // original attributes from provider
) {
}
