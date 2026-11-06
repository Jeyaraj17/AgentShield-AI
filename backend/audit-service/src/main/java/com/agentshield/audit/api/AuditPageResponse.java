package com.agentshield.audit.api;

import java.util.List;
import org.springframework.data.domain.Page;

/** Stable page wire format for the dashboard; independent of Spring Data PageImpl serialization. */
public record AuditPageResponse<T>(List<T> content,int page,int size,long totalElements,int totalPages) {
    public static <T> AuditPageResponse<T> from(Page<T> value){return new AuditPageResponse<>(value.getContent(),value.getNumber(),value.getSize(),value.getTotalElements(),value.getTotalPages());}
}
