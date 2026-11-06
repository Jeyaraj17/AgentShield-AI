package com.agentshield.identity.organization.persistence;

import java.util.UUID;

import org.springframework.data.jpa.repository.JpaRepository;

import com.agentshield.identity.organization.domain.Organization;
import java.util.Optional;

public interface OrganizationRepository extends JpaRepository<Organization, UUID> {

    boolean existsByOrganizationCode(String organizationCode);

    Optional<Organization> findByIdAndStatus(UUID id, com.agentshield.identity.organization.domain.OrganizationStatus status);
}
