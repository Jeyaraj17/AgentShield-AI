package com.agentshield.identity.config;

import java.time.Duration;
import java.util.Set;

import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;

final class SpaClientRegistrationValidator {

    private static final Duration ACCESS_TOKEN_LIFETIME = Duration.ofMinutes(10);

    private SpaClientRegistrationValidator() { }

    static void validate(RegisteredClient client, String redirectUri, String scope) {
        boolean valid = client.getRedirectUris().equals(Set.of(redirectUri))
                && client.getClientAuthenticationMethods().equals(Set.of(ClientAuthenticationMethod.NONE))
                && client.getAuthorizationGrantTypes().equals(Set.of(AuthorizationGrantType.AUTHORIZATION_CODE))
                && client.getScopes().equals(Set.of(scope))
                && client.getPostLogoutRedirectUris().isEmpty()
                && client.getClientSecret() == null
                && client.getClientSettings().isRequireProofKey()
                && !client.getClientSettings().isRequireAuthorizationConsent()
                && client.getTokenSettings().getAccessTokenTimeToLive().equals(ACCESS_TOKEN_LIFETIME)
                && client.getTokenSettings().getAccessTokenFormat().equals(
                        org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat.SELF_CONTAINED)
                && !client.getTokenSettings().isReuseRefreshTokens();
        if (!valid) {
            throw new IllegalStateException(
                    "Persisted React OAuth client settings differ from configured secure settings");
        }
    }

    static void validateRegisteredClientIds(Set<String> registeredClientIds, Set<String> expectedClientIds) {
        if (!registeredClientIds.equals(expectedClientIds)) {
            throw new IllegalStateException("Persisted OAuth clients do not match the configured SPA, Runtime Gateway, and agent credentials");
        }
    }
}
