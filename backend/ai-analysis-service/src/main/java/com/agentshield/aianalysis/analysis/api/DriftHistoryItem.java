package com.agentshield.aianalysis.analysis.api;

import java.time.Instant;
import java.util.UUID;
import java.util.Map;
public record DriftHistoryItem(UUID observationId,UUID agentId,int toolCallCount,int errorCount,int driftScore,boolean driftDetected,
        Map<String,Integer> actionDistribution,Instant createdAt) { }
