package com.agentshield.identity.config;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;

import org.junit.jupiter.api.Test;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.AuthorizationGrantType;

class ClientSecretRotationTests {
    private final BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();

    @Test
    void previousSecretAuthorizesOneWayReplacementWithNewHash() {
        RegisteredClientRepository repository = org.mockito.Mockito.mock(RegisteredClientRepository.class);
        RegisteredClient existing = client("old-secret");

        JwtConfiguration.rotateClientSecretIfAuthorized(repository, existing, "new-secret", "old-secret", encoder,
                "secret mismatch");

        var saved = org.mockito.ArgumentCaptor.forClass(RegisteredClient.class);
        verify(repository).save(saved.capture());
        assertTrue(encoder.matches("new-secret", saved.getValue().getClientSecret()));
        assertTrue(!encoder.matches("old-secret", saved.getValue().getClientSecret()));
    }

    @Test
    void currentSecretIsIdempotentAndDoesNotWrite() {
        RegisteredClientRepository repository = org.mockito.Mockito.mock(RegisteredClientRepository.class);
        RegisteredClient existing = client("current-secret");

        JwtConfiguration.rotateClientSecretIfAuthorized(repository, existing, "current-secret", "", encoder,
                "secret mismatch");

        verifyNoInteractions(repository);
    }

    @Test
    void unknownPreviousSecretFailsClosed() {
        RegisteredClientRepository repository = org.mockito.Mockito.mock(RegisteredClientRepository.class);
        RegisteredClient existing = client("stored-secret");

        assertThrows(IllegalStateException.class, () -> JwtConfiguration.rotateClientSecretIfAuthorized(
                repository, existing, "new-secret", "wrong-old-secret", encoder, "secret mismatch"));
        verifyNoInteractions(repository);
    }

    private RegisteredClient client(String secret) {
        return RegisteredClient.withId("client-id").clientId("runtime-client")
                .clientName("Runtime client").clientSecret(encoder.encode(secret))
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS).scope("test")
                .build();
    }
}
