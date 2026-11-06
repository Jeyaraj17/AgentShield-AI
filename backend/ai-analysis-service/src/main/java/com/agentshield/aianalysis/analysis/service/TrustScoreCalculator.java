package com.agentshield.aianalysis.analysis.service;

import java.util.LinkedHashMap;
import java.util.Map;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import com.agentshield.aianalysis.analysis.domain.AnalysisRecord;
import com.agentshield.aianalysis.analysis.domain.BehaviorObservation;

@Component
public class TrustScoreCalculator {
    private final double securityWeight,policyWeight,reliabilityWeight,outputWeight,driftWeight;
    public TrustScoreCalculator(@Value("${agentshield.analysis.trust.weights.security:0.25}") double security,
            @Value("${agentshield.analysis.trust.weights.policy:0.20}") double policy,
            @Value("${agentshield.analysis.trust.weights.reliability:0.20}") double reliability,
            @Value("${agentshield.analysis.trust.weights.output:0.20}") double output,
            @Value("${agentshield.analysis.trust.weights.drift:0.15}") double drift) {
        double total=security+policy+reliability+output+drift;
        if(security<0||policy<0||reliability<0||output<0||drift<0||total<=0) throw new IllegalArgumentException("Trust-score weights must be nonnegative and have a positive sum");
        securityWeight=security/total;policyWeight=policy/total;reliabilityWeight=reliability/total;outputWeight=output/total;driftWeight=drift/total;
    }
    public Result calculate(AnalysisRecord latestPrompt,AnalysisRecord latestResponse,AnalysisRecord latestHallucination,
            BehaviorObservation latestBehavior,int totalCalls,int totalErrors,int totalViolations) {
        Map<String,Integer> factors=new LinkedHashMap<>();Map<String,String> explanations=new LinkedHashMap<>();
        int security=latestPrompt==null?50:100-(latestPrompt.getRiskScore()==null?0:latestPrompt.getRiskScore());
        int policy=totalCalls==0?50:clamp(100-(int)Math.round(100.0*totalViolations/totalCalls));
        int reliability=totalCalls==0?50:clamp(100-(int)Math.round(100.0*totalErrors/totalCalls));
        int output=latestHallucination!=null?100-latestHallucination.getRiskScore():latestResponse!=null?100-latestResponse.getRiskScore():50;
        int drift=latestBehavior==null?50:100-latestBehavior.getDriftScore();
        factors.put("securityBehavior",clamp(security));factors.put("policyCompliance",clamp(policy));factors.put("reliability",clamp(reliability));
        factors.put("outputQuality",clamp(output));factors.put("driftStability",clamp(drift));
        explanations.put("securityBehavior",latestPrompt==null?"No prompt-risk observations yet.":"Inverse of latest prompt injection risk score.");
        explanations.put("policyCompliance",totalCalls==0?"No policy behavior observations yet.":"Based on gateway-reported policy violations per tool call.");
        explanations.put("reliability",totalCalls==0?"No execution observations yet.":"Based on gateway-reported errors per tool call.");
        explanations.put("outputQuality",latestHallucination!=null?"Inverse of latest evidence-based hallucination risk estimate.":latestResponse!=null?"Inverse of latest response toxicity risk estimate.":"No output-quality observations yet.");
        explanations.put("driftStability",latestBehavior==null?"No behavior baseline observations yet.":"Inverse of the latest deterministic drift score.");
        double weighted=securityWeight*security+policyWeight*policy+reliabilityWeight*reliability+outputWeight*output+driftWeight*drift;
        return new Result(clamp((int)Math.round(weighted)),Map.copyOf(factors),Map.copyOf(explanations));
    }
    private static int clamp(int score){return Math.max(0,Math.min(100,score));}
    public record Result(int score,Map<String,Integer> factors,Map<String,String> explanations) { }
}
