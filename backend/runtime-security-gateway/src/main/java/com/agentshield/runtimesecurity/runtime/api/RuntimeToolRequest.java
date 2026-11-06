package com.agentshield.runtimesecurity.runtime.api;

import java.util.Map;
import java.util.UUID;

public record RuntimeToolRequest(UUID organizationId,UUID agentId,String action,String resourceId,
        Map<String,Object> input,String correlationId) {}
