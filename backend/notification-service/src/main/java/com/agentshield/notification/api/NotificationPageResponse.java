package com.agentshield.notification.api;

import java.util.List;
import org.springframework.data.domain.Page;

/** Stable page contract for browser consumers. */
public record NotificationPageResponse<T>(List<T> content,int page,int size,long totalElements,int totalPages) {
    public static <T> NotificationPageResponse<T> from(Page<T> value){return new NotificationPageResponse<>(value.getContent(),value.getNumber(),value.getSize(),value.getTotalElements(),value.getTotalPages());}
}
