package com.agentshield.audit.api;

public record AuditSummaryResponse(long totalEvents,long authorizationAllow,long authorizationDeny,
                                  long executionSucceeded,long executionFailed,long aiThreats) { }
