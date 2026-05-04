package com.hdl.authutils.permission.aspect;

import com.hdl.authutils.permission.annotation.HasPermission;
import org.aspectj.lang.JoinPoint;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.annotation.Before;
import org.aspectj.lang.reflect.MethodSignature;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;

import java.lang.reflect.Method;

/**
 * AOP aspect that enforces {@link HasPermission} annotations.
 * <p>
 * Performs string match against SecurityContext.authorities — zero DB calls.
 * Permissions are already resolved and cached by TokenAuthenticationFilter.
 * <p>
 * Checks method-level annotation first, then class-level.
 */
@Aspect
public class PermissionAspect {

    @Before("@within(com.hdl.authutils.permission.annotation.HasPermission) || "
            + "@annotation(com.hdl.authutils.permission.annotation.HasPermission)")
    public void checkPermission(JoinPoint joinPoint) {
        HasPermission annotation = resolveAnnotation(joinPoint);
        if (annotation == null) return;

        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth == null || !auth.isAuthenticated()) {
            throw new AccessDeniedException("Not authenticated");
        }

        String required = annotation.module() + ":" + annotation.action();
        boolean authorized = auth.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .anyMatch(required::equals);

        if (!authorized) {
            throw new AccessDeniedException("Missing permission: " + required);
        }
    }

    /**
     * Resolve @HasPermission from method first, then class.
     * Method-level annotation takes precedence over class-level.
     */
    private HasPermission resolveAnnotation(JoinPoint joinPoint) {
        // Check method-level first
        if (joinPoint.getSignature() instanceof MethodSignature methodSig) {
            Method method = methodSig.getMethod();
            HasPermission methodAnnotation = method.getAnnotation(HasPermission.class);
            if (methodAnnotation != null) {
                return methodAnnotation;
            }
        }

        // Fall back to class-level
        return joinPoint.getTarget().getClass().getAnnotation(HasPermission.class);
    }
}
