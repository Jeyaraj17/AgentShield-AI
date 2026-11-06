package com.agentshield.aianalysis.security;

import java.util.UUID;

public record AnalysisPrincipal(UUID organizationId, UUID agentId) { }
