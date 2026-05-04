package com.hdl.authutils.oauth2.mapper;

import com.hdl.authutils.oauth2.model.OAuth2UserInfo;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.core.user.OAuth2User;

import java.util.Map;

/**
 * Default mapper for standard OIDC-compliant providers (Google, Microsoft, etc.).
 * <p>
 * Uses standard OIDC claims: sub, email, name, picture.
 * Falls back to common OAuth2 attribute names for non-OIDC providers.
 * <p>
 * This mapper acts as a fallback — if no project-defined mapper supports a provider,
 * this mapper handles it.
 */
public class DefaultOidcUserInfoMapper implements OAuth2UserInfoMapper {

    /**
     * Supports all providers as fallback.
     * Project-defined mappers with {@code supports() == true} take priority.
     */
    @Override
    public boolean supports(String registrationId) {
        return true;
    }

    @Override
    public OAuth2UserInfo map(OAuth2User oAuth2User, String registrationId) {
        Map<String, Object> attributes = oAuth2User.getAttributes();

        // OIDC user — use standard claims
        if (oAuth2User instanceof OidcUser oidcUser) {
            return new OAuth2UserInfo(
                    oidcUser.getEmail(),
                    oidcUser.getFullName(),
                    oidcUser.getPicture(),
                    oidcUser.getSubject(),
                    registrationId,
                    attributes
            );
        }

        // Plain OAuth2 user — try common attribute names
        return new OAuth2UserInfo(
                getStringAttribute(attributes, "email"),
                getStringAttribute(attributes, "name", "login", "display_name"),
                getStringAttribute(attributes, "avatar_url", "picture", "avatar"),
                getStringAttribute(attributes, "id", "sub"),
                registrationId,
                attributes
        );
    }

    private String getStringAttribute(Map<String, Object> attributes, String... keys) {
        for (String key : keys) {
            Object value = attributes.get(key);
            if (value != null) {
                return String.valueOf(value);
            }
        }
        return null;
    }
}
