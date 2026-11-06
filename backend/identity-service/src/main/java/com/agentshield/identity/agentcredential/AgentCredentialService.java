package com.agentshield.identity.agentcredential;

import java.security.SecureRandom;
import java.util.Base64;
import java.util.UUID;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import com.agentshield.identity.agentcredential.api.AgentCredentialResponse;
import com.agentshield.identity.agentcredential.domain.AgentCredential;
import com.agentshield.identity.agentcredential.domain.AgentCredentialStatus;
import com.agentshield.identity.agentcredential.persistence.AgentCredentialRepository;
import com.agentshield.identity.organization.domain.OrganizationStatus;
import com.agentshield.identity.organization.persistence.OrganizationRepository;

@Service
public class AgentCredentialService {
    private static final java.time.Duration AGENT_ACCESS_TOKEN_TTL = java.time.Duration.ofSeconds(30);
    private static final SecureRandom RANDOM=new SecureRandom();
    private final AgentCredentialRepository credentials;
    private final RegisteredClientRepository clients;
    private final PasswordEncoder encoder;
    private final AgentDirectoryVerifier agents;
    private final OrganizationRepository organizations;
    public AgentCredentialService(AgentCredentialRepository credentials, RegisteredClientRepository clients,
            PasswordEncoder encoder, AgentDirectoryVerifier agents,OrganizationRepository organizations) {
        this.credentials=credentials; this.clients=clients; this.encoder=encoder; this.agents=agents; this.organizations=organizations;
    }
    @Transactional
    public AgentCredentialResponse issue(UUID agentId, UUID organizationId, String bearer) {
        if(!agents.isActiveAgent(agentId,organizationId,bearer)) throw new IllegalArgumentException("Active agent was not verified in the organization");
        UUID id=UUID.randomUUID(); String clientId="agent-"+id; byte[] bytes=new byte[32]; RANDOM.nextBytes(bytes);
        String secret=Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
        RegisteredClient client=RegisteredClient.withId(id.toString()).clientId(clientId).clientName("Agent credential "+id)
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS).scope("agentshield.agent")
                .clientSecret(encoder.encode(secret))
                .tokenSettings(TokenSettings.builder().accessTokenTimeToLive(AGENT_ACCESS_TOKEN_TTL).build()).build();
        clients.save(client);
        AgentCredential credential=credentials.saveAndFlush(new AgentCredential(clientId,agentId,organizationId));
        return new AgentCredentialResponse(credential.getId(),clientId,secret,agentId,organizationId,credential.getCreatedAt());
    }
    @Transactional
    public void revoke(UUID credentialId, UUID agentId, UUID organizationId) {
        AgentCredential credential=credentials.findByIdAndAgentIdAndOrganizationId(credentialId,agentId,organizationId)
                .orElseThrow(() -> new IllegalArgumentException("Credential was not found"));
        credential.revoke(); credentials.save(credential);
    }
    @Transactional(readOnly=true)
    public AgentCredential activeForClient(String clientId) {
        AgentCredential credential=credentials.findByClientIdAndStatus(clientId,AgentCredentialStatus.ACTIVE)
                .orElseThrow(() -> new IllegalArgumentException("Agent credential is inactive"));
        boolean organizationActive=organizations.findById(credential.getOrganizationId())
                .map(organization->organization.getStatus()==OrganizationStatus.ACTIVE).orElse(false);
        if(!organizationActive) throw new IllegalArgumentException("Agent organization binding is inactive");
        return credential;
    }
}
