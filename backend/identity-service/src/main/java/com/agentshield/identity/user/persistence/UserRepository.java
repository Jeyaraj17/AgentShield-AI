package com.agentshield.identity.user.persistence;

import java.util.Optional;
import java.util.UUID;

import org.springframework.data.jpa.repository.JpaRepository;

import com.agentshield.identity.user.domain.User;

public interface UserRepository extends JpaRepository<User, UUID> {

    boolean existsByEmailNormalized(String emailNormalized);

    Optional<User> findByEmailNormalized(String emailNormalized);
}
