package com.agentshield.audit.persistence;

import java.time.Instant;
import java.util.Collection;
import java.util.UUID;
import org.springframework.data.jpa.domain.Specification;
import com.agentshield.events.contract.EventType;

public final class AuditEventSpecifications {
    private AuditEventSpecifications() { }
    public static Specification<AuditEventEntity> filters(UUID org,EventType type,UUID agent,Instant from,Instant to,String outcome,Collection<EventType> memberTypes) {
        return (root,query,cb) -> {
            var p=cb.equal(root.get("organizationId"),org);
            if(type!=null) p=cb.and(p,cb.equal(root.get("eventType"),type));
            if(agent!=null) p=cb.and(p,cb.equal(root.get("agentId"),agent));
            if(from!=null) p=cb.and(p,cb.greaterThanOrEqualTo(root.get("eventTimestamp"),from));
            if(to!=null) p=cb.and(p,cb.lessThanOrEqualTo(root.get("eventTimestamp"),to));
            if(outcome!=null) p=cb.and(p,cb.or(cb.equal(root.get("executionOutcome"),outcome),cb.equal(root.get("decision"),outcome)));
            if(memberTypes!=null) p=cb.and(p,root.get("eventType").in(memberTypes));
            return p;
        };
    }
}
