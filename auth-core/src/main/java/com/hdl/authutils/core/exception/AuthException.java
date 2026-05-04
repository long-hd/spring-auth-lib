package com.hdl.authutils.core.exception;

/**
 * Base exception for auth-lib.
 * Extends RuntimeException — unchecked, project catches via @ExceptionHandler.
 */
public class AuthException extends RuntimeException {

    public AuthException(String message) {
        super(message);
    }

    public AuthException(String message, Throwable cause) {
        super(message, cause);
    }
}
