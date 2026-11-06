package com.agentshield.runtimesecurity.runtime.service;

import org.springframework.http.HttpStatus;

public final class RuntimeExceptions {
    private RuntimeExceptions() {}
    public static class ResourceNotFound extends RuntimeException { public ResourceNotFound() { super("Execution not found"); } }
    public static class AccessDenied extends RuntimeException { public AccessDenied() { super("Access denied"); } }
    public static class ServiceUnavailable extends RuntimeException {
        private final String reasonCode;
        public ServiceUnavailable(String reasonCode) { super("A required security service is unavailable"); this.reasonCode=reasonCode; }
        public String reasonCode() { return reasonCode; }
        public HttpStatus status() { return HttpStatus.SERVICE_UNAVAILABLE; }
    }
}
