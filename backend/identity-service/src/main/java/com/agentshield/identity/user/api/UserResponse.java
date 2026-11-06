package com.agentshield.identity.user.api;

import java.time.Instant;
import java.util.UUID;

import com.agentshield.identity.user.domain.User;
import com.agentshield.identity.user.domain.UserStatus;

public record UserResponse(
        UUID id,
        String email,
        String firstName,
        String lastName,
        UserStatus status,
        Instant createdAt,
        Instant updatedAt) {

    public static UserResponse from(User user) {
        return new UserResponse(
                user.getId(),
                user.getEmailNormalized(),
                user.getFirstName(),
                user.getLastName(),
                user.getStatus(),
                user.getCreatedAt(),
                user.getUpdatedAt());
    }
}
