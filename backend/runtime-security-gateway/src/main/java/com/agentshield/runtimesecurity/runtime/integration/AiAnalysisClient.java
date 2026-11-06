package com.agentshield.runtimesecurity.runtime.integration;

import java.time.Instant;
import java.util.Map;
import java.util.UUID;

public interface AiAnalysisClient {
    AnalysisResult analyzePrompt(UUID organizationId, UUID agentId, String prompt, String serviceToken,
            String agentAssertion, String correlationId);

    AnalysisResult analyzeResponse(UUID organizationId, UUID agentId, String response, String serviceToken,
            String agentAssertion, String correlationId);

    record AnalysisResult(UUID analysisId, UUID organizationId, UUID agentId, String analysisType,
            Integer riskScore, Map<String, Object> result, Instant createdAt) { }
}
