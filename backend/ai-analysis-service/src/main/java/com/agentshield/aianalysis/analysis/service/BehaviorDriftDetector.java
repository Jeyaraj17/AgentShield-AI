package com.agentshield.aianalysis.analysis.service;

import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.LinkedHashMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import com.agentshield.aianalysis.analysis.api.BehaviorAnalysisRequest;
import com.agentshield.aianalysis.analysis.domain.BehaviorObservation;

@Component
public class BehaviorDriftDetector {
    private final int minimumSamples; private final double threshold;
    private static final Pattern ACTION_COUNT=Pattern.compile("\"([^\"]+)\"\\s*:\\s*(\\d+)");
    public BehaviorDriftDetector(@Value("${agentshield.analysis.behavior.minimum-samples:5}") int minimumSamples,
            @Value("${agentshield.analysis.behavior.drift-threshold:2.5}") double threshold) {
        this.minimumSamples=minimumSamples;this.threshold=threshold;
    }
    public Result evaluate(BehaviorAnalysisRequest current,List<BehaviorObservation> history) {
        if(history.size()<minimumSamples) return new Result(false,0,"INSUFFICIENT_BASELINE","A baseline is not yet available; drift scoring starts after enough observations.");
        double maxZ=0; boolean novelAction=false;
        double[] calls=history.stream().mapToDouble(BehaviorObservation::getToolCallCount).toArray();
        double[] errors=history.stream().mapToDouble(o->o.getToolCallCount()==0?0:(double)o.getErrorCount()/o.getToolCallCount()).toArray();
        maxZ=Math.max(maxZ,zScore(current.toolCallCount(),calls));
        double[] unusual=history.stream().mapToDouble(BehaviorObservation::getUnusualActivityCount).toArray();
        maxZ=Math.max(maxZ,zScore(current.unusualActivityCount(),unusual));
        double currentError=current.toolCallCount()==0?0:(double)current.errorCount()/current.toolCallCount();
        maxZ=Math.max(maxZ,zScore(currentError,errors));
        Set<String> known=history.stream().flatMap(o->distributionKeys(o.getActionDistributionJson()).stream()).collect(Collectors.toSet());
        novelAction=current.actionDistribution().entrySet().stream().anyMatch(e->e.getValue()>0&&!known.contains(e.getKey()));
        if(novelAction) maxZ=Math.max(maxZ,threshold+1);
        for(String action:known) {
            double[] baseline=history.stream().mapToDouble(o->proportion(o,action)).toArray();
            double currentShare=current.toolCallCount()==0?0:(double)current.actionDistribution().getOrDefault(action,0)/current.toolCallCount();
            maxZ=Math.max(maxZ,zScore(currentShare,baseline));
        }
        int score=(int)Math.max(0,Math.min(100,Math.round(maxZ/Math.max(threshold,0.1)*50)));
        boolean drift=maxZ>=threshold;
        return new Result(drift,score,drift?"STATISTICAL_DEVIATION":"WITHIN_BASELINE",drift?
                "Observed behavior differs from the recent baseline using a deterministic standardized-deviation threshold.":
                "Observed metrics remain within the configured baseline threshold.");
    }
    private double zScore(double current,double[] samples) {
        double mean=java.util.Arrays.stream(samples).average().orElse(0),variance=java.util.Arrays.stream(samples).map(v->(v-mean)*(v-mean)).average().orElse(0);
        double sd=Math.sqrt(variance); return sd<1e-9?(Math.abs(current-mean)<1e-9?0:Math.abs(current-mean)/Math.max(1.0,Math.abs(mean)*0.1)):Math.abs(current-mean)/sd;
    }
    private Set<String> distributionKeys(String json) {
        return parseDistribution(json).keySet();
    }
    private double proportion(BehaviorObservation o,String action){return o.getToolCallCount()==0?0:parseDistribution(o.getActionDistributionJson()).getOrDefault(action,0)/(double)o.getToolCallCount();}
    private Map<String,Integer> parseDistribution(String json){Map<String,Integer> values=new LinkedHashMap<>();Matcher m=ACTION_COUNT.matcher(json);while(m.find())try{values.put(m.group(1),Integer.parseInt(m.group(2)));}catch(NumberFormatException ignored){}return values;}
    public record Result(boolean driftDetected,int driftScore,String reasonCode,String explanation) { }
}
