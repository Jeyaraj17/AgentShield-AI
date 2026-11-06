package com.agentshield.aianalysis.analysis.api;

import java.util.UUID;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import java.time.Instant;
import org.springframework.web.bind.annotation.RestController;
import jakarta.validation.Valid;
import com.agentshield.aianalysis.analysis.service.AnalysisService;
import com.agentshield.aianalysis.security.AnalysisPrincipal;
import com.agentshield.aianalysis.security.AnalysisPrincipalResolver;

@RestController
@RequestMapping("/api/v1")
@Validated
public class AnalysisController {
    private final AnalysisService service; private final AnalysisPrincipalResolver principals;
    public AnalysisController(AnalysisService service,AnalysisPrincipalResolver principals){this.service=service;this.principals=principals;}

    @PostMapping("/analysis/prompts") @ResponseStatus(HttpStatus.CREATED)
    public AnalysisResponse prompt(@AuthenticationPrincipal Jwt gateway,@RequestHeader("X-Agent-Assertion") String assertion,
            @RequestHeader("X-Organization-ID") String organizationId,@RequestHeader("X-Agent-ID") String agentId,
            @Valid @RequestBody PromptAnalysisRequest request){AnalysisPrincipal p=principals.forGateway(gateway,assertion,organizationId,agentId);return service.analyzePrompt(p.organizationId(),p.agentId(),request);}
    @PostMapping("/analysis/responses") @ResponseStatus(HttpStatus.CREATED)
    public AnalysisResponse response(@AuthenticationPrincipal Jwt gateway,@RequestHeader("X-Agent-Assertion") String assertion,
            @RequestHeader("X-Organization-ID") String organizationId,@RequestHeader("X-Agent-ID") String agentId,
            @Valid @RequestBody ResponseAnalysisRequest request){AnalysisPrincipal p=principals.forGateway(gateway,assertion,organizationId,agentId);return service.analyzeResponse(p.organizationId(),p.agentId(),request);}
    @PostMapping("/analysis/hallucinations") @ResponseStatus(HttpStatus.CREATED)
    public AnalysisResponse hallucination(@AuthenticationPrincipal Jwt gateway,@RequestHeader("X-Agent-Assertion") String assertion,
            @RequestHeader("X-Organization-ID") String organizationId,@RequestHeader("X-Agent-ID") String agentId,
            @Valid @RequestBody HallucinationAnalysisRequest request){AnalysisPrincipal p=principals.forGateway(gateway,assertion,organizationId,agentId);return service.analyzeHallucination(p.organizationId(),p.agentId(),request);}
    @PostMapping("/analysis/behavior") @ResponseStatus(HttpStatus.CREATED)
    public AnalysisResponse behavior(@AuthenticationPrincipal Jwt gateway,@RequestHeader("X-Agent-Assertion") String assertion,
            @RequestHeader("X-Organization-ID") String organizationId,@RequestHeader("X-Agent-ID") String agentId,
            @Valid @RequestBody BehaviorAnalysisRequest request){AnalysisPrincipal p=principals.forGateway(gateway,assertion,organizationId,agentId);return service.analyzeBehavior(p.organizationId(),p.agentId(),request);}

    @GetMapping("/agents/{agentId}/trust-score")
    public TrustScoreResponse trust(@AuthenticationPrincipal Jwt jwt,@PathVariable UUID agentId){return service.trustScore(principals.organizationFromUser(jwt),agentId,jwt.getTokenValue());}
    @GetMapping("/agents/{agentId}/risk-history")
    public java.util.List<RiskHistoryItem> riskHistory(@AuthenticationPrincipal Jwt jwt,@PathVariable UUID agentId){return service.riskHistory(principals.organizationFromUser(jwt),agentId);}
    @GetMapping("/agents/{agentId}/drift-history")
    public java.util.List<DriftHistoryItem> driftHistory(@AuthenticationPrincipal Jwt jwt,@PathVariable UUID agentId){return service.driftHistory(principals.organizationFromUser(jwt),agentId);}

    @GetMapping("/analysis/findings")
    public DashboardPage<AnalysisFindingItem> findings(@AuthenticationPrincipal Jwt jwt,@RequestParam(required=false) UUID agentId,
            @RequestParam(required=false) String category,@RequestParam(required=false) String severity,
            @RequestParam(required=false) Instant from,@RequestParam(required=false) Instant to,
            @RequestParam(defaultValue="0") int page,@RequestParam(defaultValue="20") int size) {
        return service.dashboardFindings(principals.organizationFromUser(jwt),agentId,category,severity,from,to,page(page,size));
    }
    @GetMapping("/analysis/risk-history")
    public DashboardPage<AnalysisFindingItem> riskHistory(@AuthenticationPrincipal Jwt jwt,@RequestParam(required=false) UUID agentId,
            @RequestParam(required=false) Instant from,@RequestParam(required=false) Instant to,
            @RequestParam(defaultValue="0") int page,@RequestParam(defaultValue="20") int size) {
        return service.dashboardRiskHistory(principals.organizationFromUser(jwt),agentId,from,to,page(page,size));
    }
    @GetMapping("/analysis/drift-history")
    public DashboardPage<DriftHistoryItem> driftHistory(@AuthenticationPrincipal Jwt jwt,@RequestParam(required=false) UUID agentId,
            @RequestParam(required=false) Boolean detected,@RequestParam(required=false) Instant from,@RequestParam(required=false) Instant to,
            @RequestParam(defaultValue="0") int page,@RequestParam(defaultValue="20") int size) {
        return service.dashboardDriftHistory(principals.organizationFromUser(jwt),agentId,detected,from,to,page(page,size));
    }
    @GetMapping("/analysis/trust-history")
    public DashboardPage<TrustScoreHistoryItem> trustHistory(@AuthenticationPrincipal Jwt jwt,@RequestParam(required=false) Instant from,
            @RequestParam(required=false) Instant to,@RequestParam(defaultValue="0") int page,@RequestParam(defaultValue="20") int size) {
        return service.trustHistory(principals.organizationFromUser(jwt),from,to,page(page,size));
    }
    @GetMapping("/analysis/trust-scores")
    public DashboardPage<TrustScoreHistoryItem> trustScores(@AuthenticationPrincipal Jwt jwt,@RequestParam(defaultValue="0") int page,
            @RequestParam(defaultValue="20") int size) {
        return service.trustHistory(principals.organizationFromUser(jwt),null,null,page(page,size));
    }
    private static PageRequest page(int page,int size) {
        if(page<0||size<1||size>100)throw new org.springframework.web.server.ResponseStatusException(HttpStatus.BAD_REQUEST,"Invalid pagination");
        return PageRequest.of(page,size,Sort.by(Sort.Direction.DESC,"createdAt"));
    }
}
