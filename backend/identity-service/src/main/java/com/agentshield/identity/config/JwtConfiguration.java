package com.agentshield.identity.config;

import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.UUID;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JwtClaimValidator;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.boot.ApplicationRunner;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.agentshield.identity.auth.InvalidTenantAuthorizationException;
import com.agentshield.identity.auth.TenantAuthorizationService;
import com.agentshield.identity.agentcredential.AgentCredentialService;

import static org.springframework.security.oauth2.core.AuthorizationGrantType.AUTHORIZATION_CODE;
import static org.springframework.security.oauth2.core.ClientAuthenticationMethod.NONE;

@Configuration
public class JwtConfiguration {

    private static final String SCOPE = "agentshield.api";

    @Bean
    SigningKeyRing signingKeyRing(
            Environment environment,
            @Value("${agentshield.security.jwt.private-key-base64:}") String privateKeyBase64,
            @Value("${agentshield.security.jwt.public-key-base64:}") String publicKeyBase64,
            @Value("${agentshield.security.jwt.previous-public-keys:}") String previousPublicKeys,
            @Value("${agentshield.security.jwt.generate-ephemeral-key:false}") boolean generateEphemeralKey,
            @Value("${agentshield.security.jwt.key-id:agentshield-rsa-key-1}") String keyId) {
        String[] profiles = environment.getActiveProfiles();
        boolean developmentProfiles = profiles.length > 0
                && java.util.Arrays.stream(profiles).allMatch(profile -> profile.equals("local") || profile.equals("test"));
        if (generateEphemeralKey && !developmentProfiles) {
            throw new IllegalStateException("Ephemeral signing keys are only permitted in local/test profiles");
        }
        if (keyId == null || !keyId.matches("[A-Za-z0-9._-]{1,100}")) {
            throw new IllegalStateException("AUTH_SIGNING_KEY_ID must be a valid non-empty key identifier");
        }

        try {
            RSAPublicKey publicKey;
            RSAPrivateKey privateKey;
            if (generateEphemeralKey) {
                KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
                generator.initialize(2048);
                KeyPair pair = generator.generateKeyPair();
                publicKey = (RSAPublicKey) pair.getPublic();
                privateKey = (RSAPrivateKey) pair.getPrivate();
            } else {
                if (privateKeyBase64.isBlank() || publicKeyBase64.isBlank()) {
                    throw new IllegalStateException(
                            "AUTH_SIGNING_PRIVATE_KEY_BASE64 and AUTH_SIGNING_PUBLIC_KEY_BASE64 are required");
                }
                KeyFactory keyFactory = KeyFactory.getInstance("RSA");
                privateKey = (RSAPrivateKey) keyFactory.generatePrivate(
                        new PKCS8EncodedKeySpec(Base64.getDecoder().decode(privateKeyBase64)));
                publicKey = (RSAPublicKey) keyFactory.generatePublic(
                        new X509EncodedKeySpec(Base64.getDecoder().decode(publicKeyBase64)));
            }

            if (publicKey.getModulus().bitLength() < 2048 || privateKey.getModulus().bitLength() < 2048) {
                throw new IllegalStateException("RSA signing keys must be at least 2048 bits");
            }
            verifyKeyPair(publicKey, privateKey);
            RSAKey active = new RSAKey.Builder(publicKey)
                    .privateKey(privateKey)
                    .keyUse(KeyUse.SIGNATURE)
                    .algorithm(com.nimbusds.jose.JWSAlgorithm.RS256)
                    .keyID(keyId)
                    .build();
            List<RSAKey> keys = new ArrayList<>();
            keys.add(active);
            Set<String> keyIds = new HashSet<>();
            keyIds.add(keyId);
            if (!previousPublicKeys.isBlank()) {
                for (String encodedEntry : previousPublicKeys.split(";")) {
                    String[] parts = encodedEntry.split(":", 2);
                    if (parts.length != 2 || parts[1].isBlank() || !parts[0].matches("[A-Za-z0-9._-]{1,100}")
                            || !keyIds.add(parts[0])) {
                        throw new IllegalStateException("Previous signing key configuration is invalid");
                    }
                    RSAPublicKey previous = (RSAPublicKey) KeyFactory.getInstance("RSA").generatePublic(
                            new X509EncodedKeySpec(Base64.getDecoder().decode(parts[1])));
                    if (previous.getModulus().bitLength() < 2048) {
                        throw new IllegalStateException("RSA signing keys must be at least 2048 bits");
                    }
                    keys.add(new RSAKey.Builder(previous)
                            .keyUse(KeyUse.SIGNATURE)
                            .algorithm(com.nimbusds.jose.JWSAlgorithm.RS256)
                            .keyID(parts[0])
                            .build());
                }
            }
            return new SigningKeyRing(active, List.copyOf(keys));
        } catch (IllegalStateException exception) {
            throw exception;
        } catch (Exception exception) {
            throw new IllegalStateException("Unable to initialize RSA signing keys", exception);
        }
    }

    @Bean
    JWKSource<SecurityContext> jwkSource(SigningKeyRing signingKeyRing) {
        JWKSet keySet = new JWKSet(signingKeyRing.keys().stream()
                .map(key -> (com.nimbusds.jose.jwk.JWK) key).toList());
        return (selector, context) -> selector.select(keySet);
    }

    @Bean
    JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource,
            SigningKeyRing signingKeyRing,
            AuthorizationServerSettings settings,
            @Value("${agentshield.security.audience}") String audience,
            com.agentshield.identity.auth.TenantAuthorizationService tenantAuthorizationService) {
        requireConfigured("AUTH_AUDIENCE", audience);
        NimbusJwtDecoder decoder = NimbusJwtDecoder.withJwkSource(jwkSource)
                .jwsAlgorithm(SignatureAlgorithm.RS256)
                .build();
        decoder.setJwtValidator(new org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator<>(
                JwtValidators.createDefaultWithIssuer(settings.getIssuer()),
                new JwtClaimValidator<List<String>>("aud", values -> values != null && values.contains(audience)),
                tenantClaimValidator(tenantAuthorizationService)));
        return new KeyIdValidatingJwtDecoder(decoder, signingKeyRing.keys().stream().map(RSAKey::getKeyID).collect(
                java.util.stream.Collectors.toUnmodifiableSet()));
    }

    @Bean
    OAuth2TokenCustomizer<JwtEncodingContext> accessTokenCustomizer(
            TenantAuthorizationService tenantAuthorizationService,
            AgentCredentialService agentCredentialService,
            @Value("${agentshield.security.audience}") String audience,
            @Value("${agentshield.security.agent.audience}") String agentAudience,
            @Value("${agentshield.security.agent-management.audience}") String agentManagementAudience,
            @Value("${agentshield.security.policy.audience}") String policyAudience,
            @Value("${agentshield.security.runtime-gateway.client-id:agentshield-runtime-gateway}") String gatewayClientId,
            @Value("${agentshield.security.runtime-gateway.analysis-client-id:agentshield-runtime-gateway-analysis}") String analysisGatewayClientId,
            @Value("${agentshield.security.ai-analysis.audience:ai-analysis-api}") String analysisAudience,
            SigningKeyRing signingKeyRing) {
        return context -> {
            context.getJwsHeader()
                    .algorithm(SignatureAlgorithm.RS256)
                    .keyId(signingKeyRing.active().getKeyID());
            if (!OAuth2TokenType.ACCESS_TOKEN.equals(context.getTokenType())) {
                return;
            }

            RegisteredClient client=context.getRegisteredClient();
            if (client != null && client.getAuthorizationGrantTypes().contains(AuthorizationGrantType.CLIENT_CREDENTIALS)) {
                try {
                    String clientId=client.getClientId();
                    if (clientId.startsWith("agent-")) {
                        var credential=agentCredentialService.activeForClient(clientId);
                        context.getClaims().subject(credential.getAgentId().toString())
                                .audience(List.of(agentAudience)).claim("agent_id",credential.getAgentId().toString())
                                .claim("organization_id",credential.getOrganizationId().toString())
                                .claim("identity_type","agent").claim("token_type","agent")
                                .claim("agent_role","AGENT");
                        return;
                    }
                    if (analysisGatewayClientId.equals(clientId)
                            && "AgentShield Runtime Gateway AI Analysis".equals(client.getClientName())) {
                        if (!context.getAuthorizedScopes().equals(Set.of("analysis.evaluate")))
                            throw new InvalidTenantAuthorizationException();
                        context.getClaims().subject(clientId).audience(List.of(analysisAudience))
                                .claim("client_id",clientId).claim("service_role","RUNTIME_GATEWAY_ANALYSIS")
                                .claim("identity_type","service").claim("token_type","service")
                                .claim("scope",List.of("analysis.evaluate"));
                        return;
                    }
                    if (!gatewayClientId.equals(clientId) || !"AgentShield Runtime Security Gateway".equals(client.getClientName()))
                        throw new InvalidTenantAuthorizationException();
                    java.util.Set<String> scopes=context.getAuthorizedScopes();
                    String targetAudience=scopes.contains("policy.evaluate")?policyAudience:
                            scopes.contains("agents.read")?agentManagementAudience:null;
                    if(targetAudience==null || scopes.size()!=1) throw new InvalidTenantAuthorizationException();
                    context.getClaims().subject(client.getClientId()).audience(List.of(targetAudience))
                            .claim("client_id",client.getClientId()).claim("service_role","RUNTIME_GATEWAY")
                            .claim("identity_type","service").claim("token_type","service")
                            .claim("scope",List.copyOf(scopes));
                    return;
                } catch (RuntimeException exception) {
                    throw new OAuth2AuthenticationException(new OAuth2Error(OAuth2ErrorCodes.INVALID_GRANT,
                            "Client identity is not active", null));
                }
            }

            OAuth2Authorization authorization = context.getAuthorization();
            OAuth2AuthorizationRequest request = authorization == null
                    ? null
                    : authorization.getAttribute(OAuth2AuthorizationRequest.class.getName());
            Object selectedOrganization = request == null
                    ? null
                    : request.getAdditionalParameters().get("organization_id");
            try {
                if (selectedOrganization == null) {
                    throw new InvalidTenantAuthorizationException();
                }
                TenantAuthorizationService.VerifiedTenant tenant = tenantAuthorizationService.verify(
                        context.getPrincipal().getName(), selectedOrganization.toString());
                context.getClaims()
                        .subject(tenant.userId().toString())
                        .audience(List.of(audience))
                        .claim("user_id", tenant.userId().toString())
                        .claim("organization_id", tenant.organizationId().toString())
                        .claim("organization_role", tenant.role()).claim("identity_type","user").claim("token_type","user");
            } catch (InvalidTenantAuthorizationException exception) {
                throw new OAuth2AuthenticationException(
                        new OAuth2Error(OAuth2ErrorCodes.INVALID_GRANT, "Organization access is not available", null));
            }
        };
    }

    @Bean
    ApplicationRunner registerReactSpa(
            RegisteredClientRepository clients,
            org.springframework.jdbc.core.JdbcTemplate jdbcTemplate,
            Environment environment,
            @Value("${agentshield.security.spa.client-id}") String clientId,
            @Value("${agentshield.security.spa.redirect-uri}") String redirectUri,
            @Value("${agentshield.security.audience}") String audience,
            @Value("${agentshield.security.agent.audience}") String agentAudience,
            @Value("${agentshield.security.agent-management.audience}") String agentManagementAudience,
            @Value("${agentshield.security.policy.audience}") String policyAudience,
            @Value("${agentshield.security.runtime-gateway.client-id:agentshield-runtime-gateway}") String gatewayClientId,
            @Value("${agentshield.security.runtime-gateway.client-secret}") String gatewaySecret,
            @Value("${agentshield.security.runtime-gateway.previous-client-secret:}") String previousGatewaySecret,
            @Value("${agentshield.security.runtime-gateway.scopes:policy.evaluate,agents.read}") String gatewayScopes,
            @Value("${agentshield.security.runtime-gateway.analysis-client-id:agentshield-runtime-gateway-analysis}") String analysisClientId,
            @Value("${agentshield.security.runtime-gateway.analysis-client-secret:}") String analysisSecret,
            @Value("${agentshield.security.runtime-gateway.analysis-previous-client-secret:}") String previousAnalysisSecret,
            @Value("${agentshield.security.ai-analysis.audience:ai-analysis-api}") String analysisAudience,
            PasswordEncoder passwordEncoder) {
        return arguments -> {
            requireConfigured("AUTH_SPA_CLIENT_ID", clientId);
            requireConfigured("AUTH_SPA_REDIRECT_URI", redirectUri);
            requireConfigured("AUTH_AUDIENCE", audience);
            requireConfigured("RUNTIME_GATEWAY_CLIENT_ID",gatewayClientId);
            requireConfigured("RUNTIME_GATEWAY_ANALYSIS_CLIENT_ID",analysisClientId);
            if(!analysisClientId.matches("[A-Za-z0-9][A-Za-z0-9._-]{2,99}")||analysisClientId.startsWith("agent-")
                    ||analysisClientId.equals(gatewayClientId)||analysisClientId.equals(clientId))
                throw new IllegalStateException("Runtime Gateway AI Analysis client ID must be distinct");
            boolean localOnly=environment.getActiveProfiles().length>0&&java.util.Arrays.stream(environment.getActiveProfiles())
                    .allMatch(p->p.equals("local")||p.equals("test"));
            if(Set.of(audience,agentAudience,agentManagementAudience,policyAudience).contains(analysisAudience))
                throw new IllegalStateException("AI Analysis audience must be distinct from other service audiences");
            boolean gatewayAlreadyRegistered=clients.findByClientId(gatewayClientId)!=null;
            if(gatewaySecret.isBlank()&&(!localOnly||gatewayAlreadyRegistered)) requireConfigured("RUNTIME_GATEWAY_CLIENT_SECRET",gatewaySecret);
            boolean analysisClientAlreadyRegistered=clients.findByClientId(analysisClientId)!=null;
            if(analysisSecret.isBlank()&&(!localOnly||analysisClientAlreadyRegistered)) requireConfigured("RUNTIME_GATEWAY_ANALYSIS_CLIENT_SECRET",analysisSecret);
            requireConfigured("AI_ANALYSIS_AUDIENCE",analysisAudience);
            validateRedirectUri(redirectUri, environment);

            RegisteredClient existing = clients.findByClientId(clientId);
            if (existing != null) {
                SpaClientRegistrationValidator.validate(existing, redirectUri, SCOPE);
                if(!gatewaySecret.isBlank()) registerRuntimeGatewayClient(clients,gatewayClientId,gatewaySecret,previousGatewaySecret,gatewayScopes,passwordEncoder);
                if(!analysisSecret.isBlank()) registerAnalysisGatewayClient(clients,analysisClientId,analysisSecret,previousAnalysisSecret,passwordEncoder);
                migrateAgentCredentialTokenLifetimes(jdbcTemplate, clients);
                validateAllClientIds(jdbcTemplate,clientId,gatewayClientId,analysisClientId);
                return;
            }

            String registeredId = UUID.nameUUIDFromBytes(clientId.getBytes(StandardCharsets.UTF_8)).toString();
            RegisteredClient client = RegisteredClient.withId(registeredId)
                    .clientId(clientId)
                    .clientName("AgentShield React SPA")
                    .clientAuthenticationMethod(NONE)
                    .authorizationGrantType(AUTHORIZATION_CODE)
                    .redirectUri(redirectUri)
                    .scope(SCOPE)
                    .clientSettings(ClientSettings.builder()
                            .requireProofKey(true)
                            .requireAuthorizationConsent(false)
                            .build())
                    .tokenSettings(TokenSettings.builder()
                            .accessTokenTimeToLive(java.time.Duration.ofMinutes(10))
                            .reuseRefreshTokens(false)
                            .build())
                    .build();
            clients.save(client);
            if(!gatewaySecret.isBlank()) registerRuntimeGatewayClient(clients,gatewayClientId,gatewaySecret,previousGatewaySecret,gatewayScopes,passwordEncoder);
            if(!analysisSecret.isBlank()) registerAnalysisGatewayClient(clients,analysisClientId,analysisSecret,previousAnalysisSecret,passwordEncoder);
            migrateAgentCredentialTokenLifetimes(jdbcTemplate, clients);
            validateAllClientIds(jdbcTemplate,clientId,gatewayClientId,analysisClientId);
        };
    }

    private static void validateAllClientIds(org.springframework.jdbc.core.JdbcTemplate jdbcTemplate,String spaId,String gatewayId,String analysisId) {
        Set<String> persisted=new HashSet<>(jdbcTemplate.queryForList("SELECT client_id FROM oauth2_registered_client",String.class));
        Set<String> agentClients=new HashSet<>(jdbcTemplate.queryForList("SELECT client_id FROM agent_credentials",String.class));
        Set<String> unclassified=new HashSet<>(persisted); unclassified.remove(spaId); unclassified.remove(gatewayId); unclassified.remove(analysisId);
        Set<String> expectedAgentClients=new HashSet<>(agentClients);
        for(String id:unclassified) {
            if(!id.matches("agent-[0-9a-fA-F-]{36}")) throw new IllegalStateException("Unexpected OAuth client registration is present");
            try { UUID.fromString(id.substring("agent-".length())); } catch(IllegalArgumentException exception) { throw new IllegalStateException("Agent OAuth client identifier is invalid"); }
            expectedAgentClients.add(id); // An orphaned revoked registration remains unable to mint tokens without an active credential binding.
        }
        Set<String> expected=new HashSet<>(expectedAgentClients); expected.add(spaId);
        if(persisted.contains(gatewayId)) expected.add(gatewayId);
        if(persisted.contains(analysisId)) expected.add(analysisId);
        SpaClientRegistrationValidator.validateRegisteredClientIds(persisted,expected);
    }

    private static void registerRuntimeGatewayClient(RegisteredClientRepository clients,String clientId,String secret,
            String previousSecret, String scopes,PasswordEncoder encoder) {
        Set<String> expectedScopes=java.util.Arrays.stream(scopes.split(",")).map(String::trim).filter(s->!s.isEmpty()).collect(java.util.stream.Collectors.toUnmodifiableSet());
        if(!expectedScopes.equals(Set.of("policy.evaluate","agents.read"))) throw new IllegalStateException("Runtime Gateway scopes must be policy.evaluate and agents.read");
        RegisteredClient existing=clients.findByClientId(clientId);
        if(existing!=null) {
            boolean valid=existing.getAuthorizationGrantTypes().equals(Set.of(AuthorizationGrantType.CLIENT_CREDENTIALS))
                    && existing.getClientAuthenticationMethods().equals(Set.of(ClientAuthenticationMethod.CLIENT_SECRET_BASIC))
                    && existing.getScopes().equals(expectedScopes) && "AgentShield Runtime Security Gateway".equals(existing.getClientName());
            if(!valid) throw new IllegalStateException("Persisted Runtime Gateway client configuration is unsafe or drifted");
            rotateClientSecretIfAuthorized(clients, existing, secret, previousSecret, encoder,
                    "Persisted Runtime Gateway client secret does not match configured credentials");
            return;
        }
        clients.save(RegisteredClient.withId(UUID.nameUUIDFromBytes(clientId.getBytes(StandardCharsets.UTF_8)).toString())
                .clientId(clientId).clientName("AgentShield Runtime Security Gateway")
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .scope("policy.evaluate").scope("agents.read").clientSecret(encoder.encode(secret))
                .tokenSettings(TokenSettings.builder().accessTokenTimeToLive(java.time.Duration.ofMinutes(3)).build()).build());
    }

    private static void registerAnalysisGatewayClient(RegisteredClientRepository clients,String clientId,String secret,String previousSecret,PasswordEncoder encoder) {
        RegisteredClient existing=clients.findByClientId(clientId);
        if(existing!=null) {
            boolean valid=existing.getAuthorizationGrantTypes().equals(Set.of(AuthorizationGrantType.CLIENT_CREDENTIALS))
                    && existing.getClientAuthenticationMethods().equals(Set.of(ClientAuthenticationMethod.CLIENT_SECRET_BASIC))
                    && existing.getScopes().equals(Set.of("analysis.evaluate"))
                    && "AgentShield Runtime Gateway AI Analysis".equals(existing.getClientName())
                    && existing.getTokenSettings().getAccessTokenTimeToLive().equals(java.time.Duration.ofMinutes(2));
            if(!valid) throw new IllegalStateException("Persisted AI Analysis Gateway client configuration is unsafe or drifted");
            rotateClientSecretIfAuthorized(clients, existing, secret, previousSecret, encoder,
                    "Persisted AI Analysis client secret does not match configured credentials");
            return;
        }
        clients.save(RegisteredClient.withId(UUID.nameUUIDFromBytes(clientId.getBytes(StandardCharsets.UTF_8)).toString())
                .clientId(clientId).clientName("AgentShield Runtime Gateway AI Analysis")
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS).scope("analysis.evaluate")
                .clientSecret(encoder.encode(secret))
                .tokenSettings(TokenSettings.builder().accessTokenTimeToLive(java.time.Duration.ofMinutes(2)).build()).build());
    }

    static void rotateClientSecretIfAuthorized(RegisteredClientRepository clients, RegisteredClient existing,
            String currentSecret, String previousSecret, PasswordEncoder encoder, String errorMessage) {
        if (encoder.matches(currentSecret, existing.getClientSecret())) return;
        if (previousSecret == null || previousSecret.isBlank()
                || !encoder.matches(previousSecret, existing.getClientSecret())) {
            throw new IllegalStateException(errorMessage);
        }
        clients.save(RegisteredClient.from(existing).clientSecret(encoder.encode(currentSecret)).build());
    }

    private static void migrateAgentCredentialTokenLifetimes(org.springframework.jdbc.core.JdbcTemplate jdbcTemplate,
            RegisteredClientRepository clients) {
        java.time.Duration target = java.time.Duration.ofSeconds(30);
        for (String clientId : jdbcTemplate.queryForList("SELECT client_id FROM agent_credentials", String.class)) {
            RegisteredClient existing = clients.findByClientId(clientId);
            if (existing == null) continue;
            if (!existing.getAuthorizationGrantTypes().equals(Set.of(AuthorizationGrantType.CLIENT_CREDENTIALS))
                    || !existing.getClientAuthenticationMethods().equals(Set.of(ClientAuthenticationMethod.CLIENT_SECRET_BASIC))
                    || !existing.getScopes().equals(Set.of("agentshield.agent"))) {
                throw new IllegalStateException("Persisted agent credential client configuration is unsafe");
            }
            if (!existing.getTokenSettings().getAccessTokenTimeToLive().equals(target)) {
                clients.save(RegisteredClient.from(existing)
                        .tokenSettings(TokenSettings.builder().accessTokenTimeToLive(target).build()).build());
            }
        }
    }

    private static void verifyKeyPair(RSAPublicKey publicKey, RSAPrivateKey privateKey) throws JOSEException {
        try {
            byte[] challenge = UUID.randomUUID().toString().getBytes(StandardCharsets.UTF_8);
            Signature signer = Signature.getInstance("SHA256withRSA");
            signer.initSign(privateKey);
            signer.update(challenge);
            byte[] signature = signer.sign();
            Signature verifier = Signature.getInstance("SHA256withRSA");
            verifier.initVerify(publicKey);
            verifier.update(challenge);
            if (!verifier.verify(signature)) {
                throw new IllegalStateException("RSA signing keys do not match");
            }
        } catch (IllegalStateException exception) {
            throw exception;
        } catch (Exception exception) {
            throw new IllegalStateException("Unable to verify RSA signing key pair", exception);
        }
    }

    private static void requireConfigured(String name, String value) {
        if (value == null || value.isBlank()) {
            throw new IllegalStateException("Required authentication setting is missing: " + name);
        }
    }

    private static void validateRedirectUri(String value, Environment environment) {
        java.net.URI uri;
        try {
            uri = java.net.URI.create(value);
        } catch (IllegalArgumentException exception) {
            throw new IllegalStateException("AUTH_SPA_REDIRECT_URI must be a valid absolute URI", exception);
        }
        String[] profiles = environment.getActiveProfiles();
        boolean development = profiles.length > 0
                && java.util.Arrays.stream(profiles).allMatch(profile -> profile.equals("local") || profile.equals("test"));
        boolean localhost = "localhost".equalsIgnoreCase(uri.getHost())
                || "127.0.0.1".equals(uri.getHost()) || "::1".equals(uri.getHost())
                || "[::1]".equals(uri.getHost());
        if (uri.getHost() == null || uri.getUserInfo() != null || uri.getFragment() != null
                || uri.getQuery() != null || !("https".equalsIgnoreCase(uri.getScheme())
                        || development && localhost && "http".equalsIgnoreCase(uri.getScheme()))) {
            throw new IllegalStateException(
                    "AUTH_SPA_REDIRECT_URI must use HTTPS outside local/test and must not contain query or fragment");
        }
    }

    private static OAuth2TokenValidator<org.springframework.security.oauth2.jwt.Jwt> tenantClaimValidator(
            com.agentshield.identity.auth.TenantAuthorizationService tenants) {
        return jwt -> {
            try {
                if (!jwt.getSubject().equals(jwt.getClaimAsString("user_id"))) {
                    throw new InvalidTenantAuthorizationException();
                }
                tenants.verifyClaims(jwt.getSubject(), jwt.getClaimAsString("organization_id"),
                        jwt.getClaimAsString("organization_role"));
                return OAuth2TokenValidatorResult.success();
            } catch (RuntimeException exception) {
                return OAuth2TokenValidatorResult.failure(
                        new OAuth2Error(OAuth2ErrorCodes.INVALID_TOKEN, "Tenant access is no longer active", null));
            }
        };
    }

    record SigningKeyRing(RSAKey active, List<RSAKey> keys) { }
}
