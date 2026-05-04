package com.hdl.authutils.core.service;

import com.hdl.authutils.core.model.TokenRequest;

import java.util.Map;

/**
 * Optional hook to enrich claims for ALL token generation flows.
 * <p>
 * Use case: add tokenVersion, loginTimestamp, serverRegion...
 * to every flow (DB login, LDAP, OAuth2) without modifying each flow.
 * <p>
 * Not providing this bean = no enrichment, only additionalClaims from TokenRequest.
 * Providing this bean = lib merges enricher output into JWT claims.
 */
public interface TokenClaimsEnricher {

    /**
     * Return additional claims to merge into the JWT.
     * Called after additionalClaims from TokenRequest are applied.
     *
     * @param baseRequest the full TokenRequest (userId, username, roles, additionalClaims)
     * @return claims to add — keys that conflict with baseRequest.additionalClaims will overwrite
     */
    Map<String, Object> enrich(TokenRequest baseRequest);
}
