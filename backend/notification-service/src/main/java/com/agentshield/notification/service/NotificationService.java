package com.agentshield.notification.service;

import java.time.Instant;
import java.util.List;
import java.util.UUID;
import com.agentshield.notification.api.NotificationResponse;
import com.agentshield.notification.persistence.NotificationRepository;
import com.agentshield.notification.security.NotificationPrincipal;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

@Service
public class NotificationService {
    private static final List<String> CATEGORIES=List.of("SECURITY_DECISION","EXECUTION_FAILURE","AI_THREAT","AGENT_LIFECYCLE","POLICY_LIFECYCLE");
    private static final List<String> SEVERITIES=List.of("LOW","MEDIUM","HIGH","CRITICAL");
    private final NotificationRepository repository;
    public NotificationService(NotificationRepository repository){this.repository=repository;}
    @Transactional(readOnly=true)
    public Page<NotificationResponse> search(NotificationPrincipal p,String category,String severity,Boolean unread,Instant from,Instant to,int page,int size){
        validate(category,severity,from,to,page,size);
        return repository.search(p.organizationId(),category,severity,unread,from,to,PageRequest.of(page,size,Sort.by(Sort.Direction.DESC,"eventTimestamp")))
                .map(NotificationResponse::from);
    }
    @Transactional(readOnly=true)
    public NotificationResponse get(NotificationPrincipal p,UUID id){return NotificationResponse.from(find(p,id));}
    @Transactional
    public NotificationResponse markRead(NotificationPrincipal p,UUID id){var notification=find(p,id);notification.markRead();return NotificationResponse.from(notification);}
    @Transactional
    public int markAllRead(NotificationPrincipal p){return repository.markAllRead(p.organizationId(),Instant.now());}
    private com.agentshield.notification.persistence.NotificationEntity find(NotificationPrincipal p,UUID id){return repository.findByNotificationIdAndOrganizationId(id,p.organizationId())
            .orElseThrow(()->new ResponseStatusException(HttpStatus.NOT_FOUND,"Notification not found"));}
    private static void validate(String category,String severity,Instant from,Instant to,int page,int size){
        if(category!=null&&!CATEGORIES.contains(category))throw new ResponseStatusException(HttpStatus.BAD_REQUEST,"Unsupported category filter");
        if(severity!=null&&!SEVERITIES.contains(severity))throw new ResponseStatusException(HttpStatus.BAD_REQUEST,"Unsupported severity filter");
        if(from!=null&&to!=null&&from.isAfter(to))throw new ResponseStatusException(HttpStatus.BAD_REQUEST,"from must not be after to");
        if(page<0||size<1||size>100)throw new ResponseStatusException(HttpStatus.BAD_REQUEST,"Invalid page or size");
    }
}
