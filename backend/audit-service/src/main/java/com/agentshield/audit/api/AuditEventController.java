package com.agentshield.audit.api;

import java.time.Instant;
import java.util.UUID;
import com.agentshield.audit.security.AuditPrincipal;
import com.agentshield.audit.security.AuditPrincipal.Resolver;
import com.agentshield.audit.service.AuditEventService;
import com.agentshield.events.contract.EventType;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/audit")
@Validated
public class AuditEventController {
    private final AuditEventService service; private final Resolver principals;
    public AuditEventController(AuditEventService service,Resolver principals){this.service=service;this.principals=principals;}
    @GetMapping("/events")
    public AuditPageResponse<AuditEventResponse> search(@AuthenticationPrincipal Jwt jwt,
            @RequestParam(required=false) EventType eventType,@RequestParam(required=false) UUID agentId,
            @RequestParam(required=false) Instant from,@RequestParam(required=false) Instant to,
            @RequestParam(required=false) String outcome,@RequestParam(defaultValue="0") int page,@RequestParam(defaultValue="50") int size) {
        return AuditPageResponse.from(service.search(principals.from(jwt),eventType,agentId,from,to,outcome,page,size));
    }
    @GetMapping("/events/{eventId}")
    public AuditEventResponse get(@AuthenticationPrincipal Jwt jwt,@PathVariable UUID eventId){return service.get(principals.from(jwt),eventId);}
    @GetMapping("/summary")
    public AuditSummaryResponse summary(@AuthenticationPrincipal Jwt jwt){return service.summary(principals.from(jwt));}
}
