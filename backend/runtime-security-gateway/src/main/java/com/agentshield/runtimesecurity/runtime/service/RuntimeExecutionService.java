package com.agentshield.runtimesecurity.runtime.service;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import java.util.regex.Pattern;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import com.agentshield.runtimesecurity.runtime.api.RuntimeExecuteRequest;
import com.agentshield.runtimesecurity.runtime.api.RuntimeExecutionResponse;
import com.agentshield.runtimesecurity.runtime.api.ExecutionHistoryItem;
import com.agentshield.runtimesecurity.runtime.api.ExecutionHistoryPage;
import com.agentshield.runtimesecurity.runtime.api.RuntimeToolRequest;
import com.agentshield.runtimesecurity.runtime.audit.RuntimeAuditService;
import com.agentshield.runtimesecurity.runtime.domain.AuthorizationDecision;
import com.agentshield.runtimesecurity.runtime.domain.ExecutionResult;
import com.agentshield.runtimesecurity.runtime.domain.RuntimeExecution;
import com.agentshield.runtimesecurity.runtime.integration.AgentDirectoryClient;
import com.agentshield.runtimesecurity.runtime.integration.PolicyAuthorizationClient;
import com.agentshield.runtimesecurity.runtime.integration.RegisteredToolExecutor;
import com.agentshield.runtimesecurity.runtime.integration.GatewayServiceTokenProvider;
import com.agentshield.runtimesecurity.runtime.integration.AiAnalysisClient;
import com.agentshield.runtimesecurity.runtime.persistence.RuntimeExecutionRepository;
import static com.agentshield.runtimesecurity.runtime.service.RuntimeExceptions.AccessDenied;
import static com.agentshield.runtimesecurity.runtime.service.RuntimeExceptions.ResourceNotFound;

@Service
public class RuntimeExecutionService {
    private static final Logger log=LoggerFactory.getLogger(RuntimeExecutionService.class);
    private static final Pattern REASON=Pattern.compile("[A-Z0-9_]{1,80}");
    private final AgentDirectoryClient agents;
    private final PolicyAuthorizationClient policies;
    private final RegisteredToolExecutor tools;
    private final RuntimeAuditService audit;
    private final RuntimeExecutionRepository executions;
    private final GatewayServiceTokenProvider serviceTokens;
    private final AiAnalysisClient analysis;
    public RuntimeExecutionService(AgentDirectoryClient agents,PolicyAuthorizationClient policies,
            RegisteredToolExecutor tools,RuntimeAuditService audit,RuntimeExecutionRepository executions,
            GatewayServiceTokenProvider serviceTokens,AiAnalysisClient analysis) {
        this.agents=agents; this.policies=policies; this.tools=tools; this.audit=audit; this.executions=executions;
        this.serviceTokens=serviceTokens;this.analysis=analysis;
    }

    public ExecutionAttempt execute(UUID org,UUID agentClaim,String bearerToken,RuntimeExecuteRequest request) {
        UUID correlation=parseCorrelation(request.correlationId());
        UUID agentId=request.agentId();
        if(agentClaim==null || !agentId.equals(agentClaim))
            return denied(org,agentClaim,null,request,correlation,"AGENT_CREDENTIAL_MISMATCH",HttpStatus.FORBIDDEN);

        boolean registered;
        try { registered=tools.isRegistered(request.action()); }
        catch(RuntimeException ex) { return denied(org,agentId,null,request,correlation,"TOOL_REGISTRY_UNAVAILABLE",HttpStatus.SERVICE_UNAVAILABLE); }
        if(!registered) return denied(org,agentId,null,request,correlation,"TOOL_NOT_REGISTERED",HttpStatus.FORBIDDEN);

        AgentDirectoryClient.AgentDescriptor agent;
        try { String token=serviceTokens.tokenFor("agents.read"); agent=agents.findAgent(agentId,org,token,correlation.toString()); }
        catch(RuntimeException ex) { return denied(org,agentId,null,request,correlation,"AGENT_SERVICE_UNAVAILABLE",HttpStatus.SERVICE_UNAVAILABLE); }
        if(agent==null || !agentId.equals(agent.id()) || !org.equals(agent.organizationId()))
            return denied(org,agentId,null,request,correlation,"AGENT_NOT_FOUND_OR_OUTSIDE_ORGANIZATION",HttpStatus.NOT_FOUND);
        if(!"ACTIVE".equals(agent.status()))
            return denied(org,agentId,null,request,correlation,"AGENT_INACTIVE",HttpStatus.FORBIDDEN);
        if(!agent.capabilities().contains(request.action()))
            return denied(org,agentId,null,request,correlation,"AGENT_CAPABILITY_NOT_SUPPORTED",HttpStatus.FORBIDDEN);

        // Analysis is advisory telemetry. Its output never changes or substitutes for the Policy Engine decision.
        Object promptValue=request.input().get("prompt");
        if(promptValue instanceof String prompt&&!prompt.isBlank()) {
            try {
                analysis.analyzePrompt(org,agentId,prompt,serviceTokens.tokenFor("analysis.evaluate"),bearerToken,correlation.toString());
            } catch(RuntimeException ex) {
                log.warn("AI prompt analysis unavailable for correlation {}",correlation);
            }
        }

        PolicyAuthorizationClient.PolicyDecisionResponse policy;
        try {
            Map<String,Object> context=Map.of("input",request.input(),"resourceId",request.resourceId(),
                    "agentId",agentId.toString(),"correlationId",correlation.toString());
            String serviceToken=serviceTokens.tokenFor("policy.evaluate");
            policy=policies.authorize(org,agentId,request.action(),request.resourceId(),context,serviceToken,bearerToken,correlation.toString());
        } catch(RuntimeException ex) {
            return denied(org,agentId,null,request,correlation,"POLICY_ENGINE_UNAVAILABLE",HttpStatus.SERVICE_UNAVAILABLE);
        }
        if(!validPolicyResponse(policy))
            return denied(org,agentId,null,request,correlation,"POLICY_RESPONSE_INVALID",HttpStatus.SERVICE_UNAVAILABLE);
        if("DENY".equals(policy.decision()))
            return denied(org,agentId,null,request,correlation,policy.reasonCode(),HttpStatus.FORBIDDEN);

        RuntimeExecution stored=audit.record(org,agentId,null,request.action(),request.resourceId(),
                AuthorizationDecision.ALLOW,policy.reasonCode(),ExecutionResult.PENDING,correlation);
        Map<String,Object> result;
        try {
            RuntimeToolRequest toolRequest=new RuntimeToolRequest(org,agentId,request.action(),request.resourceId(),request.input(),correlation.toString());
            result=tools.execute(toolRequest);
            if(result==null) result=Map.of();
        } catch(RuntimeException ex) {
            RuntimeExecution completed=audit.complete(org,stored.getId(),ExecutionResult.FAILED);
            return new ExecutionAttempt(HttpStatus.BAD_GATEWAY,response(completed,null));
        }
        Object responseValue=result.get("response");
        if(responseValue instanceof String responseText&&!responseText.isBlank()) {
            try {
                analysis.analyzeResponse(org,agentId,responseText,serviceTokens.tokenFor("analysis.evaluate"),bearerToken,correlation.toString());
            } catch(RuntimeException ex) {
                log.warn("AI response analysis unavailable for correlation {}",correlation);
            }
        }
        RuntimeExecution completed=audit.complete(org,stored.getId(),ExecutionResult.SUCCEEDED);
        return new ExecutionAttempt(HttpStatus.OK,response(completed,result));
    }

    public RuntimeExecutionResponse get(UUID org,UUID agentId,UUID executionId) {
        RuntimeExecution execution=executions.findByIdAndOrganizationId(executionId,org).orElseThrow(ResourceNotFound::new);
        if(agentId==null || !agentId.equals(execution.getAgentId())) throw new ResourceNotFound();
        return response(execution,null);
    }

    @org.springframework.transaction.annotation.Transactional(readOnly=true)
    public ExecutionHistoryPage history(UUID org,UUID agentId,String outcome,String decision,Instant from,Instant to,Pageable pageable) {
        ExecutionResult result=parseEnum(outcome,ExecutionResult.class); AuthorizationDecision authDecision=parseEnum(decision,AuthorizationDecision.class);
        var page=executions.searchOrganization(org,agentId,result,authDecision,from,to,pageable);
        return new ExecutionHistoryPage(page.getContent().stream().map(this::historyItem).toList(),page.getNumber(),page.getSize(),page.getTotalElements(),page.getTotalPages());
    }

    @org.springframework.transaction.annotation.Transactional(readOnly=true)
    public ExecutionHistoryItem historyDetail(UUID org,UUID executionId) {
        return executions.findByIdAndOrganizationId(executionId,org).map(this::historyItem).orElseThrow(ResourceNotFound::new);
    }

    private ExecutionHistoryItem historyItem(RuntimeExecution e) {
        return new ExecutionHistoryItem(e.getId(),e.getAgentId(),null,e.getAction(),e.getResourceId(),e.getAuthorizationDecision(),
                e.getReasonCode(),e.getExecutionResult(),e.getCorrelationId().toString(),e.getCreatedAt(),e.getCompletedAt());
    }
    private static <T extends Enum<T>> T parseEnum(String value,Class<T> type) {
        if(value==null||value.isBlank())return null;
        try{return Enum.valueOf(type,value.toUpperCase(java.util.Locale.ROOT));}
        catch(IllegalArgumentException ex){throw new org.springframework.web.server.ResponseStatusException(org.springframework.http.HttpStatus.BAD_REQUEST,"Invalid history filter");}
    }

    private ExecutionAttempt denied(UUID org,UUID agent,UUID user,RuntimeExecuteRequest request,UUID correlation,String reason,HttpStatus status) {
        RuntimeExecution stored=audit.record(org,agent,user,request.action(),request.resourceId(),AuthorizationDecision.DENY,
                safeReason(reason),ExecutionResult.NOT_EXECUTED,correlation);
        return new ExecutionAttempt(status,response(stored,null));
    }
    private static boolean validPolicyResponse(PolicyAuthorizationClient.PolicyDecisionResponse response) {
        if(response==null || response.reasonCode()==null || !REASON.matcher(response.reasonCode()).matches() || response.matchedRules()==null) return false;
        if("ALLOW".equals(response.decision())) {
            return "MATCHED_ALLOW".equals(response.reasonCode()) && !response.matchedRules().isEmpty()
                    && response.matchedRules().stream().allMatch(rule -> validRule(rule,"ALLOW"));
        }
        if("DENY".equals(response.decision())) {
            return !"MATCHED_ALLOW".equals(response.reasonCode())
                    && response.matchedRules().stream().allMatch(rule -> validRule(rule,null));
        }
        return false;
    }
    private static boolean validRule(PolicyAuthorizationClient.MatchedRule rule,String expectedEffect) {
        return rule!=null && rule.policyId()!=null && rule.ruleId()!=null && rule.policyVersion()>0
                && ("ALLOW".equals(rule.effect()) || "DENY".equals(rule.effect()))
                && (expectedEffect==null || expectedEffect.equals(rule.effect()));
    }
    private static UUID parseCorrelation(String value) { return value==null?UUID.randomUUID():UUID.fromString(value); }
    private static String safeReason(String value) { return value!=null && REASON.matcher(value).matches()?value:"POLICY_RESPONSE_INVALID"; }
    private static RuntimeExecutionResponse response(RuntimeExecution e,Map<String,Object> toolResult) {
        return new RuntimeExecutionResponse(e.getId(),e.getOrganizationId(),e.getAgentId(),e.getAction(),
                e.getAuthorizationDecision(),e.getReasonCode(),e.getExecutionResult(),e.getCorrelationId().toString(),e.getCreatedAt(),toolResult);
    }
    public record ExecutionAttempt(HttpStatus httpStatus,RuntimeExecutionResponse response) {}
}
