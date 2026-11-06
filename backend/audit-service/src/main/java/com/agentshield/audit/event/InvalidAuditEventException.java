package com.agentshield.audit.event;

public class InvalidAuditEventException extends RuntimeException {
    public InvalidAuditEventException(String message) { super(message); }
}
