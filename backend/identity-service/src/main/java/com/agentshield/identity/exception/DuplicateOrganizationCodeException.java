package com.agentshield.identity.exception;

public class DuplicateOrganizationCodeException extends RuntimeException {

    public DuplicateOrganizationCodeException(String organizationCode) {
        super("Organization code already exists: " + organizationCode);
    }
}
