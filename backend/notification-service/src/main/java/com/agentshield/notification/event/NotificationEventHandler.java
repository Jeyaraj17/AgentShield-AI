package com.agentshield.notification.event;

import java.util.Map;
import java.util.Set;
import java.util.UUID;
import com.agentshield.events.contract.EventType;
import com.agentshield.events.contract.SecurityEvent;
import com.agentshield.events.inbox.EventHandler;
import com.agentshield.notification.persistence.NotificationEntity;
import com.agentshield.notification.persistence.NotificationRepository;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

/** Builds short, allowlisted notification text; event payloads and prompt content are never copied. */
@Component
public class NotificationEventHandler implements EventHandler {
    private static final Set<EventType> SUPPORTED=Set.of(EventType.RUNTIME_AUTHORIZATION_DENY,EventType.TOOL_EXECUTION_FAILED,
            EventType.AI_THREAT_DETECTED,EventType.AGENT_DEACTIVATED,EventType.POLICY_ACTIVATED);
    private final NotificationRepository repository;
    public NotificationEventHandler(NotificationRepository repository){this.repository=repository;}
    @Override @Transactional
    public void handle(SecurityEvent event){
        if(!SUPPORTED.contains(event.eventType()))return;
        Map<String,String> data=event.metadata();String agent=data.get("agentId");UUID agentId=agent==null?null:UUID.fromString(agent);
        UUID executionId=data.containsKey("executionId")?UUID.fromString(data.get("executionId")):null;
        String category,severity,title,description,source;
        switch(event.eventType()){
            case RUNTIME_AUTHORIZATION_DENY -> {category="SECURITY_DECISION";severity="HIGH";title="Agent action denied";description="A policy evaluation denied an agent action.";source=data.get("action");}
            case TOOL_EXECUTION_FAILED -> {category="EXECUTION_FAILURE";severity="HIGH";title="Tool execution failed";description="An approved tool execution did not complete successfully.";source=data.get("action");}
            case AI_THREAT_DETECTED -> {category="AI_THREAT";int risk=parseRisk(data.get("riskScore"));severity=risk>=90?"CRITICAL":"HIGH";title="AI security threat detected";description="AI analysis reported a security finding (risk score "+risk+"/100).";source=data.get("category");}
            case AGENT_DEACTIVATED -> {category="AGENT_LIFECYCLE";severity="MEDIUM";title="Agent deactivated";description="An agent in this organization was deactivated.";source=agent;}
            case POLICY_ACTIVATED -> {category="POLICY_LIFECYCLE";severity="MEDIUM";title="Security policy activated";description="A security policy was activated for this organization.";source=data.get("policyId");}
            default -> {return;}
        }
        repository.save(new NotificationEntity(event.eventId(),event.organizationId(),category,severity,title,description,event.eventType().name(),
                agentId,executionId,safeCode(source),event.correlationId(),event.timestamp()));
    }
    private static int parseRisk(String value){try{return Math.max(0,Math.min(100,Integer.parseInt(value)));}catch(RuntimeException ex){return 50;}}
    private static String safeCode(String value){if(value==null)return null;return value.length()<=180&&value.matches("[A-Za-z0-9_.:-]+")?value:null;}
}
