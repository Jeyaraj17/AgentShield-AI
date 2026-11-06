package com.agentshield.audit.service;

import java.time.Instant;
import java.util.List;
import java.util.UUID;
import com.agentshield.audit.api.AuditEventResponse;
import com.agentshield.audit.api.AuditSummaryResponse;
import com.agentshield.audit.persistence.AuditEventEntity;
import com.agentshield.audit.persistence.AuditEventRepository;
import com.agentshield.audit.persistence.AuditEventSpecifications;
import com.agentshield.audit.security.AuditPrincipal;
import com.agentshield.events.contract.EventType;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.http.HttpStatus;

@Service
public class AuditEventService {
    private static final List<EventType> MEMBER_EVENTS=List.of(EventType.RUNTIME_AUTHORIZATION_ALLOW,EventType.RUNTIME_AUTHORIZATION_DENY,
            EventType.TOOL_EXECUTION_SUCCEEDED,EventType.TOOL_EXECUTION_FAILED,EventType.AI_THREAT_DETECTED);
    private final AuditEventRepository repository;
    public AuditEventService(AuditEventRepository repository){this.repository=repository;}

    @Transactional(readOnly=true)
    public Page<AuditEventResponse> search(AuditPrincipal principal,EventType type,UUID agent,Instant from,Instant to,String outcome,int page,int size) {
        validate(from,to,outcome,page,size);
        var spec=spec(principal,type,agent,from,to,outcome);
        return repository.findAll(spec,PageRequest.of(page,size,Sort.by(Sort.Direction.DESC,"eventTimestamp")))
                .map(AuditEventResponse::from);
    }
    @Transactional(readOnly=true)
    public AuditEventResponse get(AuditPrincipal principal,UUID eventId) {
        AuditEventEntity event=repository.findByEventIdAndOrganizationId(eventId,principal.organizationId())
                .orElseThrow(()->new ResponseStatusException(HttpStatus.NOT_FOUND,"Audit event not found"));
        if(isMember(principal)&&!MEMBER_EVENTS.contains(event.getEventType()))
            throw new ResponseStatusException(HttpStatus.NOT_FOUND,"Audit event not found");
        return AuditEventResponse.from(event);
    }
    @Transactional(readOnly=true)
    public AuditSummaryResponse summary(AuditPrincipal principal) {
        long total=repository.count(spec(principal,null,null,null,null,null));
        long allow=repository.count(spec(principal,EventType.RUNTIME_AUTHORIZATION_ALLOW,null,null,null,null));
        long deny=repository.count(spec(principal,EventType.RUNTIME_AUTHORIZATION_DENY,null,null,null,null));
        long success=repository.count(spec(principal,EventType.TOOL_EXECUTION_SUCCEEDED,null,null,null,null));
        long failure=repository.count(spec(principal,EventType.TOOL_EXECUTION_FAILED,null,null,null,null));
        long threats=repository.count(spec(principal,EventType.AI_THREAT_DETECTED,null,null,null,null));
        return new AuditSummaryResponse(total,allow,deny,success,failure,threats);
    }
    private org.springframework.data.jpa.domain.Specification<AuditEventEntity> spec(AuditPrincipal p,EventType type,UUID agent,Instant from,Instant to,String outcome) {
        return AuditEventSpecifications.filters(p.organizationId(),type,agent,from,to,outcome,isMember(p)?MEMBER_EVENTS:null);
    }
    private static boolean isMember(AuditPrincipal p){return "MEMBER".equals(p.role());}
    private static void validate(Instant from,Instant to,String outcome,int page,int size) {
        if(from!=null&&to!=null&&from.isAfter(to)) throw new ResponseStatusException(HttpStatus.BAD_REQUEST,"from must not be after to");
        if(outcome!=null&&!List.of("ALLOW","DENY","SUCCEEDED","FAILED").contains(outcome)) throw new ResponseStatusException(HttpStatus.BAD_REQUEST,"Unsupported outcome filter");
        if(page<0||size<1||size>100) throw new ResponseStatusException(HttpStatus.BAD_REQUEST,"Invalid page or size");
    }
}
