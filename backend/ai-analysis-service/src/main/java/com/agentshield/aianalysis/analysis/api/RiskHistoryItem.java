package com.agentshield.aianalysis.analysis.api;

import java.time.Instant;
import java.util.UUID;
public record RiskHistoryItem(UUID analysisId,String analysisType,Integer riskScore,String resultJson,Instant createdAt) { }
