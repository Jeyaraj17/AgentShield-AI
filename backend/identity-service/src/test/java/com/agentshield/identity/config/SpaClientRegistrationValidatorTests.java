package com.agentshield.identity.config;

import java.time.Duration;

import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;

class SpaClientRegistrationValidatorTests {

    private static final String REDIRECT_URI = "https://app.example.test/auth/callback";
    private static final String SCOPE = "agentshield.api";

    @Test
    void exactAuthorizationCodePkceClientConfigurationIsAccepted() {
        assertDoesNotThrow(() -> SpaClientRegistrationValidator.validate(client(false), REDIRECT_URI, SCOPE));
        assertDoesNotThrow(() -> SpaClientRegistrationValidator.validateRegisteredClientIds(
                java.util.Set.of("agentshield-react-spa","agentshield-runtime-gateway"), java.util.Set.of("agentshield-react-spa","agentshield-runtime-gateway")));
    }

    @Test
    void rejectsPersistedClientWithGrantScopeRedirectOrAuthenticationDrift() {
        assertThrows(IllegalStateException.class, () -> SpaClientRegistrationValidator.validateRegisteredClientIds(
                java.util.Set.of("agentshield-react-spa", "unexpected-client"), java.util.Set.of("agentshield-react-spa","agentshield-runtime-gateway")));
        assertThrows(IllegalStateException.class,
                () -> SpaClientRegistrationValidator.validate(client(true), REDIRECT_URI, SCOPE));
        RegisteredClient wrongRedirect = RegisteredClient.from(client(false))
                .redirectUri("https://evil.example/callback").build();
        assertThrows(IllegalStateException.class,
                () -> SpaClientRegistrationValidator.validate(wrongRedirect, REDIRECT_URI, SCOPE));
        RegisteredClient missingPkce = RegisteredClient.from(client(false))
                .clientSettings(ClientSettings.builder().requireProofKey(false).build()).build();
        assertThrows(IllegalStateException.class,
                () -> SpaClientRegistrationValidator.validate(missingPkce, REDIRECT_URI, SCOPE));
        RegisteredClient extraScope = RegisteredClient.from(client(false)).scope("admin").build();
        assertThrows(IllegalStateException.class,
                () -> SpaClientRegistrationValidator.validate(extraScope, REDIRECT_URI, SCOPE));
        RegisteredClient confidentialMethod = RegisteredClient.from(client(false))
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .clientSecret("unexpected-secret").build();
        assertThrows(IllegalStateException.class,
                () -> SpaClientRegistrationValidator.validate(confidentialMethod, REDIRECT_URI, SCOPE));
    }

    private RegisteredClient client(boolean addUnsafeGrant) {
        RegisteredClient.Builder builder = RegisteredClient.withId("client-row")
                .clientId("agentshield-react-spa")
                .clientName("AgentShield React SPA")
                .clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri(REDIRECT_URI)
                .scope(SCOPE)
                .clientSettings(ClientSettings.builder().requireProofKey(true).requireAuthorizationConsent(false).build())
                .tokenSettings(TokenSettings.builder()
                        .accessTokenTimeToLive(Duration.ofMinutes(10))
                        .reuseRefreshTokens(false)
                        .build());
        if (addUnsafeGrant) {
            builder.authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN);
        }
        return builder.build();
    }
}
