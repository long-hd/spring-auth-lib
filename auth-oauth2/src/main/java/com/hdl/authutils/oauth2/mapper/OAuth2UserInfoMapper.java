package com.hdl.authutils.oauth2.mapper;

import com.hdl.authutils.oauth2.model.OAuth2UserInfo;
import org.springframework.security.oauth2.core.user.OAuth2User;

/**
 * Maps OAuth2/OIDC provider response to standardized {@link OAuth2UserInfo}.
 * <p>
 * Lib provides {@link DefaultOidcUserInfoMapper} for standard OIDC providers (Google, Microsoft).
 * Project implements custom mappers for non-standard providers (Zalo, TikTok):
 * <pre>
 * {@literal @}Component
 * public class ZaloUserInfoMapper implements OAuth2UserInfoMapper {
 *     {@literal @}Override
 *     public boolean supports(String registrationId) {
 *         return "zalo".equals(registrationId);
 *     }
 *     {@literal @}Override
 *     public OAuth2UserInfo map(OAuth2User oAuth2User, String registrationId) {
 *         // Map Zalo-specific fields
 *     }
 * }
 * </pre>
 */
public interface OAuth2UserInfoMapper {

    /**
     * Whether this mapper handles the given provider.
     *
     * @param registrationId the OAuth2 client registration ID (e.g., "google", "zalo")
     */
    boolean supports(String registrationId);

    /**
     * Map provider-specific OAuth2User to standardized OAuth2UserInfo.
     *
     * @param oAuth2User     the authenticated OAuth2 user (may be OidcUser for OIDC providers)
     * @param registrationId the OAuth2 client registration ID
     */
    OAuth2UserInfo map(OAuth2User oAuth2User, String registrationId);
}
