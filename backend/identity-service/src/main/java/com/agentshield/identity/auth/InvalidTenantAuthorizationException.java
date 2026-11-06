package com.agentshield.identity.auth;

public class InvalidTenantAuthorizationException extends RuntimeException {

    public InvalidTenantAuthorizationException() {
        super("The selected organization is not available to this user");
    }
}
