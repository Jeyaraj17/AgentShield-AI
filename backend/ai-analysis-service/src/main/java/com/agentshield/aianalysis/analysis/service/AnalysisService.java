package com.agentshield.aianalysis.analysis.service;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.springframework.http.HttpStatus;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import tools.jackson.core.JacksonException;
import tools.jackson.databind.ObjectMapper;
import com.agentshield.aianalysis.analysis.api.AnalysisResponse;
import com.agentshield.aianalysis.analysis.api.BehaviorAnalysisRequest;
import com.agentshield.aianalysis.analysis.api.DriftHistoryItem;
import com.agentshield.aianalysis.analysis.api.HallucinationAnalysisRequest;
import com.agentshield.aianalysis.analysis.api.PromptAnalysisRequest;
import com.agentshield.aianalysis.analysis.api.ResponseAnalysisRequest;
import com.agentshield.aianalysis.analysis.api.RiskHistoryItem;
import com.agentshield.aianalysis.analysis.api.TrustScoreResponse;
import com.agentshield.aianalysis.analysis.api.AnalysisFindingItem;
import com.agentshield.aianalysis.analysis.api.DashboardPage;
import com.agentshield.aianalysis.analysis.api.TrustScoreHistoryItem;
import com.agentshield.aianalysis.analysis.api.SensitiveFindingSummary;
import com.agentshield.aianalysis.analysis.domain.AnalysisRecord;
import com.agentshield.aianalysis.analysis.domain.AnalysisType;
import com.agentshield.aianalysis.analysis.domain.BehaviorObservation;
import com.agentshield.aianalysis.analysis.persistence.AnalysisRecordRepository;
import com.agentshield.aianalysis.analysis.persistence.BehaviorObservationRepository;
import com.agentshield.events.contract.EventType;
import com.agentshield.events.contract.SecurityEvent;
import com.agentshield.events.outbox.OutboxEventWriter;

@Service
public class AnalysisService {
    private final AnalysisRecordRepository records; private final BehaviorObservationRepository observations;
    private final PromptInjectionDetector injection; private final SensitiveDataDetector sensitive;
    private final HallucinationEvaluator hallucination; private final BehaviorDriftDetector drift;
    private final BiasToxicityAnalyzer bias; private final LlmModerationAssistant llm; private final TrustScoreCalculator trust;
    private final ObjectMapper mapper; private final int baselineSize; private final OutboxEventWriter events;
    private final AgentOwnershipVerifier agentOwnership;
    public AnalysisService(AnalysisRecordRepository records,BehaviorObservationRepository observations,PromptInjectionDetector injection,
            SensitiveDataDetector sensitive,HallucinationEvaluator hallucination,BehaviorDriftDetector drift,BiasToxicityAnalyzer bias,
            LlmModerationAssistant llm,TrustScoreCalculator trust,ObjectMapper mapper,
            @Value("${agentshield.analysis.behavior.baseline-size:20}") int baselineSize, OutboxEventWriter events,
            AgentOwnershipVerifier agentOwnership) {
        this.records=records;this.observations=observations;this.injection=injection;this.sensitive=sensitive;this.hallucination=hallucination;
        this.drift=drift;this.bias=bias;this.llm=llm;this.trust=trust;this.mapper=mapper;this.baselineSize=baselineSize;this.events=events;
        this.agentOwnership=agentOwnership;
        if(baselineSize<1) throw new IllegalArgumentException("Behavior baseline size must be positive");
    }

    @Transactional
    public AnalysisResponse analyzePrompt(UUID org,UUID agent,PromptAnalysisRequest request) {
        var secret=sensitive.detectAndRedact(request.prompt()); var found=injection.analyze(secret.redactedText());
        Map<String,Object> result=new LinkedHashMap<>(); result.put("category",found.category());result.put("categories",found.categories());
        result.put("riskScore",found.riskScore());result.put("explanation",found.explanation());result.put("sensitiveFindings",secret.findings());
        result.put("inputLength",request.prompt().length());
        AnalysisRecord saved=store(org,agent,AnalysisType.PROMPT,found.riskScore(),result);
        refreshTrust(org,agent); return response(saved,result);
    }

    @Transactional
    public AnalysisResponse analyzeResponse(UUID org,UUID agent,ResponseAnalysisRequest request) {
        var secret=sensitive.detectAndRedact(request.response()); var ruleResult=bias.analyze(secret.redactedText());
        String llmResult="DISABLED",llmStatus="DISABLED";
        try {
            llmResult=llm.assess(secret.redactedText());
            llmStatus=switch(llmResult) {
                case "DISABLED" -> "DISABLED";
                case "NO_ASSESSMENT" -> "NO_ASSESSMENT";
                default -> "AVAILABLE";
            };
        }
        catch(RuntimeException ex) { llmStatus="UNAVAILABLE"; }
        Map<String,Object> result=new LinkedHashMap<>();result.put("biasAndToxicityCategories",ruleResult.categories());
        result.put("riskScore",ruleResult.riskScore());result.put("explanation",ruleResult.explanation());result.put("sensitiveFindings",secret.findings());
        result.put("llmStatus",llmStatus);if("AVAILABLE".equals(llmStatus)) result.put("llmAssessment",llmResult);
        result.put("llmCanAuthorize",false);result.put("inputLength",request.response().length());
        AnalysisRecord saved=store(org,agent,AnalysisType.RESPONSE,ruleResult.riskScore(),result);
        refreshTrust(org,agent);return response(saved,result);
    }

    @Transactional
    public AnalysisResponse analyzeHallucination(UUID org,UUID agent,HallucinationAnalysisRequest request) {
        var checked=hallucination.evaluate(request.response(),request.evidence());
        List<String> safeSupported=redactClaims(checked.supportedClaims()),safeUnsupported=redactClaims(checked.unsupportedClaims()),safeConflicts=redactClaims(checked.conflictingClaims());
        List<SensitiveDataDetector.Finding> findings=new ArrayList<>();
        for(String text:concat(request.response(),request.evidence())) findings.addAll(sensitive.detectAndRedact(text).findings());
        Map<String,Object> result=new LinkedHashMap<>();result.put("supportedClaims",safeSupported);result.put("unsupportedClaims",safeUnsupported);
        result.put("conflictingClaims",safeConflicts);result.put("riskScore",checked.riskScore());result.put("explanation",checked.explanation());result.put("sensitiveFindings",findings);
        AnalysisRecord saved=store(org,agent,AnalysisType.HALLUCINATION,checked.riskScore(),result);
        refreshTrust(org,agent);return response(saved,result);
    }

    @Transactional
    public AnalysisResponse analyzeBehavior(UUID org,UUID agent,BehaviorAnalysisRequest request) {
        if(request.errorCount()>request.toolCallCount()||request.policyViolationCount()>request.toolCallCount()
                ||request.actionDistribution().values().stream().mapToInt(Integer::intValue).sum()!=request.toolCallCount())
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST,"Behavior counts must agree with total tool calls");
        List<BehaviorObservation> history=observations.findByOrganizationIdAndAgentIdOrderByCreatedAtDesc(org,agent,PageRequest.of(0,baselineSize));
        BehaviorDriftDetector.Result result=drift.evaluate(request,history);
        String distribution=serialize(request.actionDistribution());
        BehaviorObservation observation=observations.save(new BehaviorObservation(org,agent,request.toolCallCount(),request.errorCount(),
                request.policyViolationCount(),request.unusualActivityCount(),distribution,result.driftScore(),result.driftDetected()));
        Map<String,Object> body=new LinkedHashMap<>();body.put("driftDetected",result.driftDetected());body.put("driftScore",result.driftScore());
        body.put("reasonCode",result.reasonCode());body.put("explanation",result.explanation());body.put("baselineSamples",history.size());
        body.put("observationId",observation.getId());body.put("llmCanAuthorize",false);
        AnalysisRecord saved=store(org,agent,AnalysisType.BEHAVIOR,result.driftScore(),body);
        TrustScoreResponse score=refreshTrust(org,agent);body.put("trustScore",score.score());
        return response(saved,body);
    }

    @Transactional(readOnly=true)
    public TrustScoreResponse trustScore(UUID org,UUID agent,String userAccessToken) {
        agentOwnership.requireOwnedBy(org,agent,userAccessToken);
        AnalysisRecord latest=records.findFirstByOrganizationIdAndAgentIdAndTypeOrderByCreatedAtDesc(org,agent,AnalysisType.TRUST_SCORE);
        if(latest==null) return new TrustScoreResponse(org,agent,50,Map.of("securityBehavior",50,"policyCompliance",50,"reliability",50,"outputQuality",50,"driftStability",50),Map.of("status","Insufficient observations; neutral baseline score."),Instant.now());
        try {
            Map<?,?> data=mapper.readValue(latest.getResultJson(),Map.class);
            @SuppressWarnings("unchecked") Map<String,Integer> factors=(Map<String,Integer>)data.get("factors");
            @SuppressWarnings("unchecked") Map<String,String> explanations=(Map<String,String>)data.get("explanations");
            return new TrustScoreResponse(org,agent,((Number)data.get("score")).intValue(),factors,explanations,latest.getCreatedAt());
        } catch(RuntimeException ex) { throw new IllegalStateException("Stored trust score is unavailable"); }
    }

    @Transactional(readOnly=true)
    public List<RiskHistoryItem> riskHistory(UUID org,UUID agent) {
        var types=List.of(AnalysisType.PROMPT,AnalysisType.RESPONSE,AnalysisType.HALLUCINATION);
        return records.findByOrganizationIdAndAgentIdAndTypeInOrderByCreatedAtDesc(org,agent,types,PageRequest.of(0,100))
                .stream().map(r->new RiskHistoryItem(r.getId(),r.getType().name(),r.getRiskScore(),r.getResultJson(),r.getCreatedAt())).toList();
    }
    @Transactional(readOnly=true)
    public List<DriftHistoryItem> driftHistory(UUID org,UUID agent) {
        return observations.findTop20ByOrganizationIdAndAgentIdOrderByCreatedAtDesc(org,agent).stream()
                .map(this::driftItem).toList();
    }

    @Transactional(readOnly=true)
    public DashboardPage<AnalysisFindingItem> dashboardFindings(UUID org,UUID agent,String type,String severity,Instant from,Instant to,Pageable pageable) {
        if(from!=null&&to!=null&&from.isAfter(to)) throw new ResponseStatusException(HttpStatus.BAD_REQUEST,"Invalid date range");
        AnalysisType category=parseType(type);
        Integer min=null,max=null;
        if(severity!=null&&!severity.isBlank()) switch(severity.toUpperCase(java.util.Locale.ROOT)) {
            case "LOW" -> {min=0;max=29;} case "MEDIUM" -> {min=30;max=69;} case "HIGH" -> {min=70;max=89;} case "CRITICAL" -> {min=90;max=100;}
            default -> throw new ResponseStatusException(HttpStatus.BAD_REQUEST,"Invalid severity filter");
        }
        var result=records.search(org,List.of(AnalysisType.PROMPT,AnalysisType.RESPONSE,AnalysisType.HALLUCINATION),agent,category,min,max,from,to,pageable);
        List<AnalysisFindingItem> items=result.getContent().stream().map(this::findingItem).toList();
        return new DashboardPage<>(items,result.getNumber(),result.getSize(),result.getTotalElements(),result.getTotalPages());
    }

    @Transactional(readOnly=true)
    public DashboardPage<TrustScoreHistoryItem> trustHistory(UUID org,Instant from,Instant to,Pageable pageable) {
        if(from!=null&&to!=null&&from.isAfter(to)) throw new ResponseStatusException(HttpStatus.BAD_REQUEST,"Invalid date range");
        var result=records.history(org,AnalysisType.TRUST_SCORE,from,to,pageable);
        return new DashboardPage<>(result.getContent().stream().map(this::trustHistoryItem).toList(),result.getNumber(),result.getSize(),result.getTotalElements(),result.getTotalPages());
    }

    @Transactional(readOnly=true)
    public DashboardPage<AnalysisFindingItem> dashboardRiskHistory(UUID org,UUID agent,Instant from,Instant to,Pageable pageable) {
        if(from!=null&&to!=null&&from.isAfter(to)) throw new ResponseStatusException(HttpStatus.BAD_REQUEST,"Invalid date range");
        var result=records.search(org,List.of(AnalysisType.PROMPT,AnalysisType.RESPONSE,AnalysisType.HALLUCINATION),agent,null,null,null,from,to,pageable);
        return new DashboardPage<>(result.getContent().stream().map(this::findingItem).toList(),result.getNumber(),result.getSize(),result.getTotalElements(),result.getTotalPages());
    }

    @Transactional(readOnly=true)
    public DashboardPage<DriftHistoryItem> dashboardDriftHistory(UUID org,UUID agent,Boolean detected,Instant from,Instant to,Pageable pageable) {
        if(from!=null&&to!=null&&from.isAfter(to)) throw new ResponseStatusException(HttpStatus.BAD_REQUEST,"Invalid date range");
        var result=observations.search(org,agent,detected,from,to,pageable);
        return new DashboardPage<>(result.getContent().stream().map(this::driftItem).toList(),result.getNumber(),result.getSize(),result.getTotalElements(),result.getTotalPages());
    }

    private AnalysisFindingItem findingItem(AnalysisRecord record) {
        try {
            Map<?,?> data=mapper.readValue(record.getResultJson(),Map.class);
            Object cats=data.get("categories"); if(cats==null)cats=data.get("biasAndToxicityCategories");
            List<String> categories=cats instanceof List<?> list?list.stream().filter(String.class::isInstance).map(String.class::cast).toList():List.of();
            List<SensitiveFindingSummary> sensitiveFindings=new ArrayList<>();
            if(data.get("sensitiveFindings") instanceof List<?> rawFindings) for(Object finding:rawFindings) if(finding instanceof Map<?,?> item
                    &&item.get("category") instanceof String category && item.get("count") instanceof Number count)
                sensitiveFindings.add(new SensitiveFindingSummary(category,count.intValue()));
            Integer score=record.getRiskScore(); String severity=score==null?"UNKNOWN":score>=90?"CRITICAL":score>=70?"HIGH":score>=30?"MEDIUM":"LOW";
            return new AnalysisFindingItem(record.getId(),record.getAgentId(),record.getType().name(),severity,score,categories,
                    List.copyOf(sensitiveFindings),string(data.get("explanation")),strings(data.get("supportedClaims")),strings(data.get("unsupportedClaims")),
                    strings(data.get("conflictingClaims")),string(data.get("llmStatus")),record.getCreatedAt());
        } catch(RuntimeException ex) { throw new IllegalStateException("Stored analysis finding is unavailable"); }
    }
    private TrustScoreHistoryItem trustHistoryItem(AnalysisRecord record) {
        try { Map<?,?> data=mapper.readValue(record.getResultJson(),Map.class);
            @SuppressWarnings("unchecked") Map<String,Integer> factors=(Map<String,Integer>)data.get("factors");
            @SuppressWarnings("unchecked") Map<String,String> explanations=(Map<String,String>)data.get("explanations");
            return new TrustScoreHistoryItem(record.getAgentId(),((Number)data.get("score")).intValue(),factors,explanations,record.getCreatedAt());
        } catch(RuntimeException ex) { throw new IllegalStateException("Stored trust score is unavailable"); }
    }
    private DriftHistoryItem driftItem(BehaviorObservation observation) {
        try {
            Map<?,?> raw=mapper.readValue(observation.getActionDistributionJson(),Map.class);
            Map<String,Integer> distribution=new LinkedHashMap<>();
            raw.forEach((key,value)->{if(key instanceof String name&&value instanceof Number count)distribution.put(name,count.intValue());});
            return new DriftHistoryItem(observation.getId(),observation.getAgentId(),observation.getToolCallCount(),observation.getErrorCount(),
                    observation.getDriftScore(),observation.isDriftDetected(),Map.copyOf(distribution),observation.getCreatedAt());
        } catch(RuntimeException ex) { throw new IllegalStateException("Stored behavior observation is unavailable"); }
    }
    private static String string(Object value){return value instanceof String s?s:null;}
    private static List<String> strings(Object value){return value instanceof List<?> list?list.stream().filter(String.class::isInstance).map(String.class::cast).toList():List.of();}
    private static AnalysisType parseType(String value){if(value==null||value.isBlank())return null;try{return AnalysisType.valueOf(value.toUpperCase(java.util.Locale.ROOT));}catch(IllegalArgumentException ex){throw new ResponseStatusException(HttpStatus.BAD_REQUEST,"Invalid finding category");}}

    private TrustScoreResponse refreshTrust(UUID org,UUID agent) {
        AnalysisRecord prompt=records.findFirstByOrganizationIdAndAgentIdAndTypeOrderByCreatedAtDesc(org,agent,AnalysisType.PROMPT);
        AnalysisRecord response=records.findFirstByOrganizationIdAndAgentIdAndTypeOrderByCreatedAtDesc(org,agent,AnalysisType.RESPONSE);
        AnalysisRecord halluc=records.findFirstByOrganizationIdAndAgentIdAndTypeOrderByCreatedAtDesc(org,agent,AnalysisType.HALLUCINATION);
        List<BehaviorObservation> all=observations.findTop20ByOrganizationIdAndAgentIdOrderByCreatedAtDesc(org,agent);
        int calls=all.stream().mapToInt(BehaviorObservation::getToolCallCount).sum(),errors=all.stream().mapToInt(BehaviorObservation::getErrorCount).sum(),violations=all.stream().mapToInt(BehaviorObservation::getPolicyViolationCount).sum();
        var calculated=trust.calculate(prompt,response,halluc,all.isEmpty()?null:all.getFirst(),calls,errors,violations);
        Map<String,Object> data=new LinkedHashMap<>();data.put("score",calculated.score());data.put("factors",calculated.factors());data.put("explanations",calculated.explanations());
        data.put("authorizationEffect","NONE"); data.put("notice","Trust score is advisory and never grants or denies authorization.");
        AnalysisRecord saved=store(org,agent,AnalysisType.TRUST_SCORE,100-calculated.score(),data);
        events.append(SecurityEvent.create(org, EventType.AGENT_TRUST_SCORE_UPDATED, null, Map.of(
                "agentId", agent.toString(), "score", Integer.toString(calculated.score()))));
        return new TrustScoreResponse(org,agent,calculated.score(),calculated.factors(),calculated.explanations(),saved.getCreatedAt());
    }
    private List<String> redactClaims(List<String> claims){return claims.stream().map(c->sensitive.detectAndRedact(c).redactedText()).toList();}
    private static List<String> concat(String response,List<String> evidence){List<String> all=new ArrayList<>(evidence);all.add(response);return all;}
    private AnalysisRecord store(UUID org,UUID agent,AnalysisType type,Integer score,Map<String,Object> result) {
        AnalysisRecord saved=records.save(new AnalysisRecord(org,agent,type,score,serialize(result)));
        if(score != null && score >= 70 && (type == AnalysisType.PROMPT || type == AnalysisType.RESPONSE || type == AnalysisType.HALLUCINATION || type == AnalysisType.BEHAVIOR)) {
            events.append(SecurityEvent.create(org, EventType.AI_THREAT_DETECTED, null, Map.of(
                    "agentId", agent.toString(), "analysisId", saved.getId().toString(), "category", type.name(), "riskScore", score.toString())));
        }
        return saved;
    }
    private String serialize(Object value){try{return mapper.writeValueAsString(value);}catch(JacksonException e){throw new IllegalStateException("Analysis result could not be stored");}}
    private AnalysisResponse response(AnalysisRecord saved,Map<String,Object> result){return new AnalysisResponse(saved.getId(),saved.getOrganizationId(),saved.getAgentId(),saved.getType().name(),saved.getRiskScore(),Map.copyOf(result),saved.getCreatedAt());}
}
