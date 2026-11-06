package com.agentshield.aianalysis.analysis.api;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

public record AnalysisFindingItem(UUID analysisId, UUID agentId, String analysisType, String severity,
        Integer riskScore, List<String> categories, List<SensitiveFindingSummary> sensitiveFindings, String explanation, List<String> supportedClaims,
        List<String> unsupportedClaims, List<String> conflictingClaims, String llmStatus, Instant createdAt) { }
