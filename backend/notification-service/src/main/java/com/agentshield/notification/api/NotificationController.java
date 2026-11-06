package com.agentshield.notification.api;

import java.time.Instant;
import java.util.Map;
import java.util.UUID;
import com.agentshield.notification.security.NotificationPrincipal;
import com.agentshield.notification.security.NotificationPrincipal.Resolver;
import com.agentshield.notification.service.NotificationService;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/notifications")
public class NotificationController {
    private final NotificationService service;private final Resolver resolver;
    public NotificationController(NotificationService service,Resolver resolver){this.service=service;this.resolver=resolver;}
    @GetMapping public NotificationPageResponse<NotificationResponse> search(@AuthenticationPrincipal Jwt jwt,@RequestParam(required=false)String category,
            @RequestParam(required=false)String severity,@RequestParam(required=false)Boolean unread,@RequestParam(required=false)Instant from,
            @RequestParam(required=false)Instant to,@RequestParam(defaultValue="0")int page,@RequestParam(defaultValue="50")int size){
        return NotificationPageResponse.from(service.search(resolver.from(jwt),category,severity,unread,from,to,page,size));
    }
    @GetMapping("/{notificationId}") public NotificationResponse get(@AuthenticationPrincipal Jwt jwt,@PathVariable UUID notificationId){return service.get(resolver.from(jwt),notificationId);}
    @PatchMapping("/{notificationId}/read") public NotificationResponse markRead(@AuthenticationPrincipal Jwt jwt,@PathVariable UUID notificationId){return service.markRead(resolver.from(jwt),notificationId);}
    @PatchMapping("/read-all") public ResponseEntity<Map<String,Integer>> markAllRead(@AuthenticationPrincipal Jwt jwt){return ResponseEntity.ok(Map.of("updated",service.markAllRead(resolver.from(jwt))));}
}
