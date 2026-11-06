package com.agentshield.notification.persistence;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface NotificationRepository extends JpaRepository<NotificationEntity,UUID> {
    Optional<NotificationEntity> findByNotificationIdAndOrganizationId(UUID notificationId,UUID organizationId);
    @Query("select n from NotificationEntity n where n.organizationId=:org "
            + "and (:category is null or n.category=:category) and (:severity is null or n.severity=:severity) "
            + "and (:unread is null or (:unread=true and n.readAt is null) or (:unread=false and n.readAt is not null)) "
            + "and (:fromTime is null or n.eventTimestamp>=:fromTime) and (:toTime is null or n.eventTimestamp<=:toTime)")
    Page<NotificationEntity> search(@Param("org") UUID organizationId,@Param("category") String category,
            @Param("severity") String severity,@Param("unread") Boolean unread,@Param("fromTime") Instant from,
            @Param("toTime") Instant to,Pageable pageable);
    @Modifying
    @Query("update NotificationEntity n set n.readAt=:readAt where n.organizationId=:org and n.readAt is null")
    int markAllRead(@Param("org") UUID organizationId,@Param("readAt") Instant readAt);
}
