package com.agentshield.aianalysis.analysis.api;

import java.time.Instant;
import java.util.Map;
import java.util.UUID;
public record AnalysisResponse(UUID analysisId, UUID organizationId, UUID agentId, String analysisType,
        Integer riskScore, Map<String,Object> result, Instant createdAt) { }
