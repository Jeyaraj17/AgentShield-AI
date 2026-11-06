package com.agentshield.aianalysis.analysis.api;

import java.time.Instant;
import java.util.Map;
import java.util.UUID;
public record TrustScoreResponse(UUID organizationId,UUID agentId,int score,Map<String,Integer> factors,
        Map<String,String> explanations,Instant calculatedAt) { }
