package com.agentshield.identity.membership.persistence;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import com.agentshield.identity.membership.domain.OrganizationMembership;

public interface OrganizationMembershipRepository extends JpaRepository<OrganizationMembership, UUID> {

    Optional<OrganizationMembership> findByUser_IdAndOrganization_Id(UUID userId, UUID organizationId);

    List<OrganizationMembership> findAllByUser_Id(UUID userId);

    List<OrganizationMembership> findAllByOrganization_Id(UUID organizationId);

    @Query("select membership from OrganizationMembership membership join fetch membership.user "
            + "where membership.organization.id = :organizationId order by membership.joinedAt asc, membership.id asc")
    List<OrganizationMembership> findDirectoryByOrganizationId(@Param("organizationId") UUID organizationId);

    boolean existsByUser_IdAndOrganization_Id(UUID userId, UUID organizationId);
}
