package com.hdl.authutils.core.filter;

import com.hdl.authutils.core.config.AuthProperties;
import com.hdl.authutils.core.model.TokenClaims;
import com.hdl.authutils.core.service.PermissionResolver;
import com.hdl.authutils.core.service.TokenService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.*;
import java.util.stream.Collectors;

/**
 * JWT authentication filter.
 * <p>
 * Reads token from request (header or cookie, based on config),
 * validates it, resolves permissions, and sets SecurityContext.
 * <p>
 * Does NOT throw exception when token is missing — lets SecurityFilterChain
 * decide whether to permit or deny the request.
 * <p>
 * SecurityContext layout after filter:
 * <ul>
 *   <li>principal = userId (Long)</li>
 *   <li>authorities = ROLE_xxx (from roles) + MODULE:ACTION (from permissions)</li>
 *   <li>details = Map{username, displayName, roles, ...additionalClaims}</li>
 * </ul>
 * <p>
 * This enables both role-based and permission-based access control:
 * <ul>
 *   <li>{@code @PreAuthorize("hasRole('ADMIN')")} — checks ROLE_ADMIN authority</li>
 *   <li>{@code @PreAuthorize("hasAuthority('SHIPMENT:CREATE')")} — checks permission authority</li>
 *   <li>{@code @HasPermission(module="SHIPMENT", action="CREATE")} — checks via AOP aspect</li>
 * </ul>
 */
public class TokenAuthenticationFilter extends OncePerRequestFilter {

    private static final Logger log = LoggerFactory.getLogger(TokenAuthenticationFilter.class);
    private static final String ROLE_PREFIX = "ROLE_";

    private final TokenService tokenService;
    private final PermissionResolver permissionResolver;
    private final TokenExtractor tokenExtractor;

    public TokenAuthenticationFilter(TokenService tokenService,
                                     PermissionResolver permissionResolver,
                                     AuthProperties properties) {
        this.tokenService = tokenService;
        this.permissionResolver = permissionResolver;

        var accessConfig = properties.getJwt().getAccessToken();
        this.tokenExtractor = new TokenExtractor(
                accessConfig.getSource(), accessConfig.getCookieName());
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain)
            throws ServletException, IOException {

        tokenExtractor.extract(request).ifPresent(token -> {
            try {
                tokenService.validateAccessToken(token).ifPresent(this::setSecurityContext);
            } catch (Exception e) {
                log.debug("Failed to process token: {}", e.getMessage());
            }
        });

        try {
            filterChain.doFilter(request, response);
        } finally {
            SecurityContextHolder.clearContext();
        }
    }

    private void setSecurityContext(TokenClaims claims) {
        List<SimpleGrantedAuthority> authorities = new ArrayList<>();

        // 1. Roles as ROLE_xxx authorities
        //    Enables: hasRole("ADMIN"), @PreAuthorize("hasRole('ADMIN')")
        if (claims.roles() != null) {
            for (String role : claims.roles()) {
                authorities.add(new SimpleGrantedAuthority(ROLE_PREFIX + role));
            }
        }

        // 2. Permissions as MODULE:ACTION authorities
        //    Enables: hasAuthority("SHIPMENT:CREATE"), @HasPermission
        Set<String> permissions = permissionResolver.resolve(claims.roles());
        for (String permission : permissions) {
            authorities.add(new SimpleGrantedAuthority(permission));
        }

        // Build details map: username, displayName, roles + additionalClaims
        Map<String, Object> details = new LinkedHashMap<>();
        if (claims.username() != null) {
            details.put("username", claims.username());
        }
        if (claims.displayName() != null) {
            details.put("displayName", claims.displayName());
        }
        if (claims.roles() != null && !claims.roles().isEmpty()) {
            details.put("roles", claims.roles());
        }
        if (claims.additionalClaims() != null) {
            details.putAll(claims.additionalClaims());
        }

        UsernamePasswordAuthenticationToken authentication =
                new UsernamePasswordAuthenticationToken(
                        claims.userId(),
                        null,
                        Collections.unmodifiableList(authorities)
                );
        authentication.setDetails(Collections.unmodifiableMap(details));

        SecurityContextHolder.getContext().setAuthentication(authentication);
    }
}
