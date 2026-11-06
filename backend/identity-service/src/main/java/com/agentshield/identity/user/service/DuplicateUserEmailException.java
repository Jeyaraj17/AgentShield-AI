package com.agentshield.identity.user.service;

public class DuplicateUserEmailException extends RuntimeException {

    public DuplicateUserEmailException(String email) {
        super("Email is already registered: " + email);
    }
}
