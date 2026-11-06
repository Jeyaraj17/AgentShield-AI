package com.agentshield.identity.auth;

import java.net.CookieManager;
import java.net.CookiePolicy;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpRequest;
import java.net.http.HttpClient;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.KeyPair;
import java.security.interfaces.RSAPrivateKey;
import java.util.Base64;
import java.time.Instant;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.security.oauth2.jwt.JwtException;

import com.agentshield.identity.config.TestKeyMaterial;
import com.agentshield.identity.agentcredential.AgentCredentialService;
import com.agentshield.identity.agentcredential.AgentDirectoryVerifier;
import com.agentshield.identity.agentcredential.persistence.AgentCredentialRepository;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import com.agentshield.identity.membership.domain.OrganizationMembership;
import com.agentshield.identity.membership.domain.OrganizationRole;
import com.agentshield.identity.membership.persistence.OrganizationMembershipRepository;
import com.agentshield.identity.organization.domain.Organization;
import com.agentshield.identity.organization.persistence.OrganizationRepository;
import com.agentshield.identity.user.domain.User;
import com.agentshield.identity.user.persistence.UserRepository;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.assertThrows;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, properties = {
        "agentshield.security.rate-limit.max-requests=200"
})
@ActiveProfiles("test")
class AuthenticationFoundationTests {

    private static final String PASSWORD = "StrongPassword1!";
    private static final String CLIENT_ID = "agentshield-react-spa";
    private static final String REDIRECT_URI = "http://localhost:3000/auth/callback";
    private static final Pattern ACCESS_TOKEN = Pattern.compile("\"access_token\"\\s*:\\s*\"([^\"]+)\"");
    private static final String PREVIOUS_KEY_ID = "agentshield-test-previous";
    private static final KeyPair PREVIOUS_KEY = TestKeyMaterial.generateKeyPair();

    @DynamicPropertySource
    static void previousSigningKey(DynamicPropertyRegistry registry) {
        registry.add("agentshield.security.jwt.previous-public-keys", () -> PREVIOUS_KEY_ID + ":"
                + Base64.getEncoder().encodeToString(PREVIOUS_KEY.getPublic().getEncoded()));
    }

    @Value("${local.server.port}")
    private int port;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private OrganizationRepository organizationRepository;

    @Autowired
    private OrganizationMembershipRepository membershipRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private JwtDecoder jwtDecoder;

    @Autowired private AgentCredentialService agentCredentialService;
    @Autowired private AgentCredentialRepository agentCredentialRepository;
    @MockitoBean private AgentDirectoryVerifier agentDirectoryVerifier;

    @Autowired
    private JdbcTemplate jdbcTemplate;

    @Autowired
    private TenantAuthorizationService tenantAuthorizationService;

    @Test
    void successfulAuthenticationProducesSignedTenantScopedJwtClaims() throws Exception {
        User user = createUser("auth-success");
        Organization organization = createOrganization("auth-success");
        membershipRepository.saveAndFlush(
                new OrganizationMembership(user, organization, OrganizationRole.ADMIN));
        assertEquals("ADMIN", tenantAuthorizationService
                .verify(user.getEmailNormalized(), organization.getId().toString()).role());
        String verifier = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~";
        HttpClient client = newHttpClient();
        authenticate(client, user.getEmailNormalized(), PASSWORD, true);

        HttpResponse<String> authorization = authorize(
                client, organization.getId().toString(), verifier, challenge(verifier));
        assertEquals(302, authorization.statusCode(), authorization.body());
        String callback = authorization.headers().firstValue("location").orElseThrow();
        String code = queryParameter(callback, "code");
        assertNotNull(code, "Authorization endpoint redirect did not contain a code: " + callback
                + " body=" + authorization.body());

        HttpResponse<String> tokenResponse = client.send(formPost("/oauth2/token",
                "grant_type", "authorization_code",
                "client_id", CLIENT_ID,
                "redirect_uri", REDIRECT_URI,
                "code", code,
                "code_verifier", verifier), HttpResponse.BodyHandlers.ofString());
        assertEquals(200, tokenResponse.statusCode(), tokenResponse.body());
        String accessToken = match(ACCESS_TOKEN, tokenResponse.body());
        assertNotNull(accessToken);
        assertTrue(!tokenResponse.body().contains("refresh_token"));

        Jwt jwt = jwtDecoder.decode(accessToken);
        assertEquals(user.getId().toString(), jwt.getSubject());
        assertEquals(user.getId().toString(), jwt.getClaimAsString("user_id"));
        assertEquals(organization.getId().toString(), jwt.getClaimAsString("organization_id"));
        assertEquals("ADMIN", jwt.getClaimAsString("organization_role"));
        assertEquals("agentshield-api", jwt.getAudience().getFirst());
        assertEquals("http://localhost:8080", jwt.getIssuer().toString());
    }

    @Test
    void authorizationChallengeUsesBrandedSpaAndResumesTheSavedOAuthRequest() throws Exception {
        User user = createUser("auth-branded-login");
        Organization organization = createOrganization("auth-branded-login");
        membershipRepository.saveAndFlush(new OrganizationMembership(user, organization, OrganizationRole.OWNER));
        HttpClient browser = newHttpClient();
        String verifier = "branded-login-verifier-abcdefghijklmnopqrstuvwxyz0123456789";

        HttpResponse<String> challenge = authorize(
                browser, organization.getId().toString(), verifier, challenge(verifier));
        assertEquals(302, challenge.statusCode());
        assertTrue(challenge.headers().firstValue("location").orElse("").endsWith("/login"));

        HttpResponse<String> login = browser.send(
                HttpRequest.newBuilder(uri("/login")).GET().build(), HttpResponse.BodyHandlers.ofString());
        assertEquals(302, login.statusCode());
        assertEquals("http://localhost:3000/sign-in?identityLogin=1",
                login.headers().firstValue("location").orElseThrow());
        assertTrue(login.body().isEmpty());
        String csrfCookieHeader = login.headers().allValues("set-cookie").stream()
                .filter(cookie -> cookie.startsWith("XSRF-TOKEN="))
                .findFirst().orElse("");
        assertTrue(csrfCookieHeader.contains("Path=/"));
        assertTrue(csrfCookieHeader.contains("SameSite=Lax"));
        assertTrue(!csrfCookieHeader.contains("HttpOnly"));
        String csrf = csrfCookie(browser);
        assertNotNull(csrf);

        HttpResponse<String> authenticated = browser.send(formPost("/login",
                "username", user.getEmailNormalized(), "password", PASSWORD, "_csrf", csrf),
                HttpResponse.BodyHandlers.ofString());
        String resumedRequest = authenticated.headers().firstValue("location").orElseThrow();
        assertRedirectStatus(authenticated.statusCode());
        URI resumedUri = URI.create(resumedRequest);
        assertEquals("/oauth2/authorize", resumedUri.getPath());
        assertTrue(resumedRequest.contains(organization.getId().toString()));

        HttpResponse<String> resumed = browser.send(HttpRequest.newBuilder(resumedUri).GET().build(),
                HttpResponse.BodyHandlers.ofString());
        assertEquals(302, resumed.statusCode());
        String callback = resumed.headers().firstValue("location").orElseThrow();
        assertTrue(callback.startsWith(REDIRECT_URI));
        String code = queryParameter(callback, "code");
        assertNotNull(code);

        HttpResponse<String> tokenResponse = browser.send(formPost("/oauth2/token",
                "grant_type", "authorization_code", "client_id", CLIENT_ID,
                "redirect_uri", REDIRECT_URI, "code", code, "code_verifier", verifier),
                HttpResponse.BodyHandlers.ofString());
        assertEquals(200, tokenResponse.statusCode(), tokenResponse.body());
        String accessToken = match(ACCESS_TOKEN, tokenResponse.body());
        assertNotNull(accessToken);
        HttpResponse<String> dashboardProfile = browser.send(HttpRequest.newBuilder(uri("/api/v1/users/me"))
                .header("Authorization", "Bearer " + accessToken).GET().build(),
                HttpResponse.BodyHandlers.ofString());
        assertEquals(200, dashboardProfile.statusCode(), dashboardProfile.body());
        assertTrue(dashboardProfile.body().contains(user.getId().toString()));
    }

    @Test
    void spaCanRequestFreshCredentialsEvenWhenAnIdentitySessionAlreadyExists() throws Exception {
        User user = createUser("auth-reauthentication");
        Organization organization = createOrganization("auth-reauthentication");
        membershipRepository.saveAndFlush(new OrganizationMembership(user, organization, OrganizationRole.OWNER));
        HttpClient browser = newHttpClient();

        String firstVerifier = "reauth-first-verifier-abcdefghijklmnopqrstuvwxyz0123456789";
        HttpResponse<String> initial = authorize(browser, organization.getId().toString(), firstVerifier,
                challenge(firstVerifier));
        assertRedirectStatus(initial.statusCode());
        HttpResponse<String> initialLogin = authenticate(browser, user.getEmailNormalized(), PASSWORD, true);
        URI firstResume = URI.create(initialLogin.headers().firstValue("location").orElseThrow());
        HttpResponse<String> firstAuthorization = browser.send(HttpRequest.newBuilder(firstResume).GET().build(),
                HttpResponse.BodyHandlers.ofString());
        assertTrue(firstAuthorization.headers().firstValue("location").orElse("").startsWith(REDIRECT_URI));

        String secondVerifier = "reauth-second-verifier-abcdefghijklmnopqrstuvwxyz0123456789";
        HttpResponse<String> forced = authorizeWithReauthentication(browser, organization.getId().toString(),
                secondVerifier, challenge(secondVerifier));
        assertRedirectStatus(forced.statusCode());
        assertTrue(forced.headers().firstValue("location").orElse("").endsWith("/login"),
                "A remembered Identity session must not bypass the explicit credential prompt");

        HttpResponse<String> secondLogin = authenticate(browser, user.getEmailNormalized(), PASSWORD, true);
        URI secondResume = URI.create(secondLogin.headers().firstValue("location").orElseThrow());
        assertTrue(secondResume.getQuery().contains("reauthenticate=true"));
        HttpResponse<String> secondAuthorization = browser.send(HttpRequest.newBuilder(secondResume).GET().build(),
                HttpResponse.BodyHandlers.ofString());
        assertTrue(secondAuthorization.headers().firstValue("location").orElse("").startsWith(REDIRECT_URI),
                "After fresh authentication, the saved PKCE authorization request should resume");
    }

    @Test
    void userBearerCanIssueCredentialThroughProtectedIdentityApiWithoutBrowserSession() throws Exception {
        User user=createUser("credential-api");
        Organization organization=createOrganization("credential-api");
        membershipRepository.saveAndFlush(new OrganizationMembership(user,organization,OrganizationRole.OWNER));
        HttpClient browser=newHttpClient();
        authenticate(browser,user.getEmailNormalized(),PASSWORD,true);
        String verifier="credential-api-verifier-abcdefghijklmnopqrstuvwxyz0123456789";
        HttpResponse<String> authorization=authorize(browser,organization.getId().toString(),verifier,challenge(verifier));
        assertEquals(302,authorization.statusCode(),authorization.body());
        String code=queryParameter(authorization.headers().firstValue("location").orElseThrow(),"code");
        HttpResponse<String> tokenResponse=browser.send(formPost("/oauth2/token","grant_type","authorization_code",
                "client_id",CLIENT_ID,"redirect_uri",REDIRECT_URI,"code",code,"code_verifier",verifier),
                HttpResponse.BodyHandlers.ofString());
        assertEquals(200,tokenResponse.statusCode(),tokenResponse.body());
        String accessToken=match(ACCESS_TOKEN,tokenResponse.body());
        UUID agent=UUID.randomUUID();
        org.mockito.Mockito.when(agentDirectoryVerifier.isActiveAgent(agent,organization.getId(),accessToken)).thenReturn(true);

        HttpRequest issue=HttpRequest.newBuilder(uri("/api/v1/organizations/"+organization.getId()+"/agents/"+agent+"/credentials"))
                .header("Authorization","Bearer "+accessToken).POST(HttpRequest.BodyPublishers.noBody()).build();
        HttpResponse<String> response=HttpClient.newHttpClient().send(issue,HttpResponse.BodyHandlers.ofString());

        assertEquals(201,response.statusCode(),response.body());
        assertTrue(response.body().contains("\"clientSecret\""));
        assertTrue(response.body().contains(agent.toString()));
        assertTrue(response.body().contains(organization.getId().toString()));
    }

    @Test
    void agentCredentialClientCredentialsIssueBoundJwtAndCannotOverrideAgentBinding() throws Exception {
        UUID agent=UUID.randomUUID(),organization=createOrganization("agent-credential").getId();
        org.mockito.Mockito.when(agentDirectoryVerifier.isActiveAgent(agent,organization,"user-token")).thenReturn(true);
        var credential=agentCredentialService.issue(agent,organization,"user-token");
        assertTrue(jdbcTemplate.queryForObject("SELECT client_secret FROM oauth2_registered_client WHERE client_id=?",String.class,credential.clientId()).startsWith("$2"));
        HttpResponse<String> response=clientCredentials(credential.clientId(),credential.clientSecret(),"agentshield.agent",UUID.randomUUID().toString());
        assertEquals(200,response.statusCode(),response.body());
        String token=ACCESS_TOKEN.matcher(response.body()).results().findFirst().orElseThrow().group(1);
        var claims=verifiedClaims(token);
        assertEquals(agent.toString(),claims.getSubject());
        assertEquals(agent.toString(),claims.getStringClaim("agent_id"));
        assertEquals(organization.toString(),claims.getStringClaim("organization_id"));
        assertEquals("agent",claims.getStringClaim("identity_type"));
        assertEquals("AGENT",claims.getStringClaim("agent_role"));
        assertEquals("agentshield-runtime-api",claims.getAudience().getFirst());
        assertTrue(claims.getExpirationTime().toInstant().isBefore(Instant.now().plusSeconds(31)),
                "Agent access tokens must have a maximum 30-second lifetime to bound revocation delay");
    }

    @Test
    void revokedAgentCredentialAndInvalidGatewaySecretCannotObtainTokens() throws Exception {
        UUID agent=UUID.randomUUID(),organization=createOrganization("agent-revoked").getId();
        org.mockito.Mockito.when(agentDirectoryVerifier.isActiveAgent(agent,organization,"user-token")).thenReturn(true);
        var credential=agentCredentialService.issue(agent,organization,"user-token");
        HttpResponse<String> invalid=clientCredentials(credential.clientId(),"incorrect-secret","agentshield.agent",null);
        assertEquals(401,invalid.statusCode());
        agentCredentialService.revoke(credential.credentialId(),agent,organization);
        HttpResponse<String> revoked=clientCredentials(credential.clientId(),credential.clientSecret(),"agentshield.agent",null);
        assertTrue(revoked.statusCode()!=200);
        HttpResponse<String> gateway=clientCredentials("agentshield-runtime-gateway","incorrect-secret","policy.evaluate",null);
        assertEquals(401,gateway.statusCode());
    }

    @Test
    void runtimeGatewayClientCredentialsIssueScopedServiceIdentity() throws Exception {
        HttpResponse<String> response=clientCredentials("agentshield-runtime-gateway","test-only-runtime-gateway-secret","policy.evaluate",null);
        assertEquals(200,response.statusCode(),response.body());
        String token=ACCESS_TOKEN.matcher(response.body()).results().findFirst().orElseThrow().group(1);
        var claims=verifiedClaims(token);
        assertEquals("agentshield-runtime-gateway",claims.getSubject());
        assertEquals("agentshield-runtime-gateway",claims.getStringClaim("client_id"));
        assertEquals("service",claims.getStringClaim("identity_type"));
        assertEquals("RUNTIME_GATEWAY",claims.getStringClaim("service_role"));
        assertEquals("policy-engine-api",claims.getAudience().getFirst());
        assertTrue(claims.getExpirationTime().toInstant().isBefore(Instant.now().plusSeconds(181)));
    }

    @Test
    void analysisGatewayClientReceivesOnlyItsDedicatedAudienceAndScope() throws Exception {
        HttpResponse<String> invalidCredentials=clientCredentials("agentshield-runtime-gateway-analysis",
                "incorrect-analysis-secret","analysis.evaluate",null);
        assertEquals(401,invalidCredentials.statusCode());
        HttpResponse<String> response=clientCredentials("agentshield-runtime-gateway-analysis",
                "test-only-runtime-gateway-analysis-secret","analysis.evaluate",null);
        assertEquals(200,response.statusCode(),response.body());
        String token=ACCESS_TOKEN.matcher(response.body()).results().findFirst().orElseThrow().group(1);
        var claims=verifiedClaims(token);
        assertEquals("agentshield-runtime-gateway-analysis",claims.getSubject());
        assertEquals("agentshield-runtime-gateway-analysis",claims.getStringClaim("client_id"));
        assertEquals("service",claims.getStringClaim("identity_type"));
        assertEquals("service",claims.getStringClaim("token_type"));
        assertEquals("RUNTIME_GATEWAY_ANALYSIS",claims.getStringClaim("service_role"));
        assertEquals("ai-analysis-api",claims.getAudience().getFirst());
        assertTrue(String.valueOf(claims.getClaim("scope")).contains("analysis.evaluate"));
        assertTrue(claims.getExpirationTime().toInstant().isBefore(Instant.now().plusSeconds(121)));
        HttpResponse<String> wrongScope=clientCredentials("agentshield-runtime-gateway-analysis",
                "test-only-runtime-gateway-analysis-secret","policy.evaluate",null);
        assertNotEquals(200,wrongScope.statusCode());
        HttpResponse<String> oldClient=clientCredentials("agentshield-runtime-gateway",
                "test-only-runtime-gateway-secret","analysis.evaluate",null);
        assertNotEquals(200,oldClient.statusCode());
    }

    private HttpResponse<String> clientCredentials(String clientId,String secret,String scope,String attemptedAgentId) throws Exception {
        String form="grant_type=client_credentials&scope="+enc(scope)+(attemptedAgentId==null?"":"&agent_id="+enc(attemptedAgentId)+"&organization_id="+enc(UUID.randomUUID().toString()));
        String basic=Base64.getEncoder().encodeToString((clientId+":"+secret).getBytes(StandardCharsets.UTF_8));
        return newHttpClient().send(HttpRequest.newBuilder(uri("/oauth2/token")).header("Authorization","Basic "+basic)
                .header("Content-Type","application/x-www-form-urlencoded").POST(HttpRequest.BodyPublishers.ofString(form)).build(),HttpResponse.BodyHandlers.ofString());
    }
    private com.nimbusds.jwt.JWTClaimsSet verifiedClaims(String token) throws Exception {
        SignedJWT signed=SignedJWT.parse(token);
        HttpResponse<String> jwks=newHttpClient().send(HttpRequest.newBuilder(uri("/oauth2/jwks")).GET().build(),HttpResponse.BodyHandlers.ofString());
        var key=com.nimbusds.jose.jwk.JWKSet.parse(jwks.body()).getKeys().stream().filter(k->k.getKeyID().equals(signed.getHeader().getKeyID())).findFirst().orElseThrow().toRSAKey();
        assertTrue(signed.verify(new com.nimbusds.jose.crypto.RSASSAVerifier(key.toRSAPublicKey())));
        return signed.getJWTClaimsSet();
    }

    @Test
    void invalidCredentialsCannotAuthenticate() throws Exception {
        User user = createUser("auth-invalid-password");
        HttpResponse<String> response = authenticate(newHttpClient(), user.getEmailNormalized(), "incorrect-password", false);
        HttpResponse<String> missing = authenticate(newHttpClient(), "unknown-" + UUID.randomUUID() + "@example.com",
                PASSWORD, false);

        assertRedirectStatus(response.statusCode());
        assertTrue(response.headers().firstValue("location").orElse("").contains("error"));
        assertEquals(response.headers().firstValue("location"), missing.headers().firstValue("location"),
                "Login failure response must not reveal whether the email exists");
    }

    @Test
    void inactiveUsersCannotAuthenticate() throws Exception {
        User user = createUser("auth-inactive");
        jdbcTemplate.update("UPDATE users SET status = 'INACTIVE' WHERE id = ?", user.getId().toString());

        HttpResponse<String> response = authenticate(newHttpClient(), user.getEmailNormalized(), PASSWORD, false);

        assertRedirectStatus(response.statusCode());
        assertTrue(response.headers().firstValue("location").orElse("").contains("error"));
    }

    @Test
    void activeUserWithoutActiveOrganizationMembershipCannotGetAuthorizationCode() throws Exception {
        User user = createUser("auth-no-membership");
        Organization organization = createOrganization("auth-no-membership");
        HttpClient client = newHttpClient();
        authenticate(client, user.getEmailNormalized(), PASSWORD, true);
        String verifier = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~";

        HttpResponse<String> response = authorize(
                client, organization.getId().toString(), verifier, challenge(verifier));

        assertEquals(403, response.statusCode(), response.body());
    }

    @Test
    void authorizationCodeFlowRejectsMissingPkceChallenge() throws Exception {
        User user = createUser("auth-no-pkce");
        Organization organization = createOrganization("auth-no-pkce");
        membershipRepository.saveAndFlush(
                new OrganizationMembership(user, organization, OrganizationRole.MEMBER));
        HttpClient client = newHttpClient();
        authenticate(client, user.getEmailNormalized(), PASSWORD, true);

        HttpResponse<String> response = authorize(client, organization.getId().toString(), null, null);

        String location = response.headers().firstValue("location").orElse("");
        assertTrue(response.statusCode() == 400 || location.contains("invalid_request")
                        || response.body().contains("invalid_request"),
                "Missing PKCE challenge must reject the authorization request: status=" + response.statusCode()
                        + ", location=" + location + ", body=" + response.body());
    }

    @Test
    void jwksEndpointIsPublicAndDoesNotPublishPrivateKeyMaterial() throws Exception {
        HttpResponse<String> response = newHttpClient().send(
                HttpRequest.newBuilder(uri("/oauth2/jwks")).GET().build(), HttpResponse.BodyHandlers.ofString());
        assertEquals(200, response.statusCode());
        assertTrue(response.body().contains("\"kty\":\"RSA\""));
        assertTrue(!response.body().contains("\"d\":"));
        assertTrue(!response.body().contains("private"));
        assertTrue(response.body().contains("\"kid\":\"agentshield-rsa-key-1\""));
        assertTrue(response.body().contains("\"kid\":\"" + PREVIOUS_KEY_ID + "\""));
    }

    @Test
    void previouslyIssuedJwtRemainsValidWhilePreviousPublicKeyIsPublished() throws Exception {
        User user = createUser("auth-rotation");
        Organization organization = createOrganization("auth-rotation");
        membershipRepository.saveAndFlush(new OrganizationMembership(user, organization, OrganizationRole.MEMBER));
        String token = signJwt(PREVIOUS_KEY.getPrivate(), PREVIOUS_KEY_ID, JWSAlgorithm.RS256,
                "http://localhost:8080", "agentshield-api", Instant.now().plusSeconds(60),
                user.getId().toString(), organization.getId().toString(), "MEMBER");

        assertEquals(user.getId().toString(), jwtDecoder.decode(token).getSubject());
    }

    @Test
    void jwtDecoderRejectsInvalidSignatureAlgorithmIssuerAudienceAndExpiry() throws Exception {
        User user = createUser("auth-jwt-negative");
        Organization organization = createOrganization("auth-jwt-negative");
        membershipRepository.saveAndFlush(new OrganizationMembership(user, organization, OrganizationRole.MEMBER));
        Instant validExpiry = Instant.now().plusSeconds(60);
        String valid = signJwt(TestKeyMaterial.activeKeyPair().getPrivate(), "agentshield-rsa-key-1",
                JWSAlgorithm.RS256, "http://localhost:8080", "agentshield-api", validExpiry,
                user.getId().toString(), organization.getId().toString(), "MEMBER");
        String unknownKid = signJwt(TestKeyMaterial.activeKeyPair().getPrivate(), "unregistered-key-id",
                JWSAlgorithm.RS256, "http://localhost:8080", "agentshield-api", validExpiry,
                user.getId().toString(), organization.getId().toString(), "MEMBER");
        assertThrows(JwtException.class, () -> jwtDecoder.decode(unknownKid));
        String[] parts = valid.split("\\.");
        parts[2] = (parts[2].charAt(0) == 'A' ? "B" : "A") + parts[2].substring(1);
        assertThrows(JwtException.class, () -> jwtDecoder.decode(String.join(".", parts)));
        String wrongAlgorithm = signJwt(TestKeyMaterial.activeKeyPair().getPrivate(), "agentshield-rsa-key-1",
                JWSAlgorithm.HS256, "http://localhost:8080", "agentshield-api", validExpiry,
                user.getId().toString(), organization.getId().toString(), "MEMBER");
        assertThrows(JwtException.class, () -> jwtDecoder.decode(wrongAlgorithm));
        String wrongIssuer = signJwt(TestKeyMaterial.activeKeyPair().getPrivate(), "agentshield-rsa-key-1",
                JWSAlgorithm.RS256, "https://wrong.example.test", "agentshield-api", validExpiry,
                user.getId().toString(), organization.getId().toString(), "MEMBER");
        assertThrows(JwtException.class, () -> jwtDecoder.decode(wrongIssuer));
        String wrongAudience = signJwt(TestKeyMaterial.activeKeyPair().getPrivate(), "agentshield-rsa-key-1",
                JWSAlgorithm.RS256, "http://localhost:8080", "wrong-audience", validExpiry,
                user.getId().toString(), organization.getId().toString(), "MEMBER");
        assertThrows(JwtException.class, () -> jwtDecoder.decode(wrongAudience));
        String expired = signJwt(TestKeyMaterial.activeKeyPair().getPrivate(), "agentshield-rsa-key-1",
                JWSAlgorithm.RS256, "http://localhost:8080", "agentshield-api", Instant.now().minusSeconds(5),
                user.getId().toString(), organization.getId().toString(), "MEMBER");
        assertThrows(JwtException.class, () -> jwtDecoder.decode(expired));
    }

    @Test
    void decoderRejectsTokensAfterUserOrMembershipBecomesInactive() throws Exception {
        User inactiveUser = createUser("auth-user-revoked");
        Organization inactiveUserOrganization = createOrganization("auth-user-revoked");
        membershipRepository.saveAndFlush(new OrganizationMembership(
                inactiveUser, inactiveUserOrganization, OrganizationRole.MEMBER));
        String inactiveUserToken = signJwt(TestKeyMaterial.activeKeyPair().getPrivate(), "agentshield-rsa-key-1",
                JWSAlgorithm.RS256, "http://localhost:8080", "agentshield-api", Instant.now().plusSeconds(60),
                inactiveUser.getId().toString(), inactiveUserOrganization.getId().toString(), "MEMBER");
        jdbcTemplate.update("UPDATE users SET status = 'INACTIVE' WHERE id = ?", inactiveUser.getId().toString());
        assertThrows(JwtException.class, () -> jwtDecoder.decode(inactiveUserToken));

        User inactiveMember = createUser("auth-membership-revoked");
        Organization inactiveMemberOrganization = createOrganization("auth-membership-revoked");
        OrganizationMembership membership = membershipRepository.saveAndFlush(new OrganizationMembership(
                inactiveMember, inactiveMemberOrganization, OrganizationRole.MEMBER));
        String inactiveMembershipToken = signJwt(TestKeyMaterial.activeKeyPair().getPrivate(), "agentshield-rsa-key-1",
                JWSAlgorithm.RS256, "http://localhost:8080", "agentshield-api", Instant.now().plusSeconds(60),
                inactiveMember.getId().toString(), inactiveMemberOrganization.getId().toString(), "MEMBER");
        jdbcTemplate.update("UPDATE organization_memberships SET membership_status = 'INACTIVE' WHERE id = ?",
                membership.getId().toString());
        assertThrows(JwtException.class, () -> jwtDecoder.decode(inactiveMembershipToken));
    }

    @Test
    void crossOrganizationSelectionCannotIssueAuthorizationCode() throws Exception {
        User user = createUser("auth-cross-organization");
        Organization memberOrganization = createOrganization("auth-cross-member");
        Organization otherOrganization = createOrganization("auth-cross-other");
        membershipRepository.saveAndFlush(new OrganizationMembership(user, memberOrganization, OrganizationRole.ADMIN));
        HttpClient client = newHttpClient();
        authenticate(client, user.getEmailNormalized(), PASSWORD, true);
        String verifier = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~";

        HttpResponse<String> response = authorize(
                client, otherOrganization.getId().toString(), verifier, challenge(verifier));

        assertEquals(403, response.statusCode());
    }

    @Test
    void corsRejectsUnapprovedOrigin() throws Exception {
        HttpResponse<String> response = newHttpClient().send(HttpRequest.newBuilder(uri("/oauth2/token"))
                .header("Origin", "https://unapproved.example.test")
                .header("Access-Control-Request-Method", "POST")
                .method("OPTIONS", HttpRequest.BodyPublishers.noBody())
                .build(), HttpResponse.BodyHandlers.ofString());
        assertEquals(403, response.statusCode());
    }

    @Test
    void opaqueOriginIsAcceptedOnlyForSameOriginLoginNavigationAndStillRequiresCsrf() throws Exception {
        User user = createUser("auth-opaque-origin");
        HttpClient browser = newHttpClient();
        HttpResponse<String> loginPage = browser.send(
                HttpRequest.newBuilder(uri("/login")).GET().build(), HttpResponse.BodyHandlers.ofString());
        assertEquals(302, loginPage.statusCode());
        String csrf = csrfCookie(browser);
        assertNotNull(csrf);

        String form = "username=" + enc(user.getEmailNormalized()) + "&password=" + enc(PASSWORD)
                + "&_csrf=" + enc(csrf);
        HttpResponse<String> validCsrf = browser.send(HttpRequest.newBuilder(uri("/login"))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .header("Origin", "null")
                .header("Sec-Fetch-Site", "same-origin")
                .header("Sec-Fetch-Mode", "navigate")
                .header("Sec-Fetch-Dest", "document")
                .header("Sec-Fetch-User", "?1")
                .POST(HttpRequest.BodyPublishers.ofString(form)).build(), HttpResponse.BodyHandlers.ofString());
        assertRedirectStatus(validCsrf.statusCode());
        assertTrue(!validCsrf.headers().firstValue("location").orElse("").contains("error"));
        assertTrue(validCsrf.headers().firstValue("Access-Control-Allow-Credentials").isEmpty());

        HttpResponse<String> missingCsrf = newHttpClient().send(HttpRequest.newBuilder(uri("/login"))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .header("Origin", "null")
                .header("Sec-Fetch-Site", "same-origin")
                .header("Sec-Fetch-Mode", "navigate")
                .header("Sec-Fetch-Dest", "document")
                .header("Sec-Fetch-User", "?1")
                .POST(HttpRequest.BodyPublishers.ofString("username=missing%40example.test&password=wrong"))
                .build(), HttpResponse.BodyHandlers.ofString());
        assertEquals(403, missingCsrf.statusCode());

        HttpResponse<String> nullOriginJwks = newHttpClient().send(HttpRequest.newBuilder(uri("/oauth2/jwks"))
                .header("Origin", "null").GET().build(), HttpResponse.BodyHandlers.ofString());
        assertEquals(403, nullOriginJwks.statusCode());
    }

    @Test
    void authorizationCodeFlowRejectsPkceDowngradeAndUnregisteredRedirect() throws Exception {
        User user = createUser("auth-pkce-downgrade");
        Organization organization = createOrganization("auth-pkce-downgrade");
        membershipRepository.saveAndFlush(new OrganizationMembership(user, organization, OrganizationRole.MEMBER));
        HttpClient client = newHttpClient();
        authenticate(client, user.getEmailNormalized(), PASSWORD, true);
        String verifier = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~";
        String challenge = challenge(verifier);

        HttpResponse<String> downgrade = authorizeWithMethod(
                client, organization.getId().toString(), verifier, challenge, "plain", REDIRECT_URI);
        assertEquals(400, downgrade.statusCode());
        HttpResponse<String> invalidRedirect = authorizeWithMethod(
                client, organization.getId().toString(), verifier, challenge, "S256", "https://evil.example/callback");
        assertTrue(invalidRedirect.statusCode() == 400
                || !invalidRedirect.headers().firstValue("location").orElse("").startsWith("https://evil.example"));
    }

    private User createUser(String prefix) {
        return userRepository.saveAndFlush(new User(
                prefix + "-" + UUID.randomUUID() + "@example.com",
                "Auth",
                "Test",
                passwordEncoder.encode(PASSWORD)));
    }

    private Organization createOrganization(String prefix) {
        String unique = UUID.randomUUID().toString();
        return organizationRepository.saveAndFlush(
                new Organization("Auth " + prefix, "a-" + unique, null));
    }

    private HttpResponse<String> authenticate(HttpClient client, String email, String password, boolean successful)
            throws Exception {
        HttpResponse<String> loginPage = client.send(
                HttpRequest.newBuilder(uri("/login")).GET().build(), HttpResponse.BodyHandlers.ofString());
        assertEquals(302, loginPage.statusCode());
        assertEquals("http://localhost:3000/sign-in?identityLogin=1",
                loginPage.headers().firstValue("location").orElseThrow());
        String csrf = csrfCookie(client);
        assertNotNull(csrf, "Identity must issue a CSRF cookie for the React login form");
        HttpResponse<String> response = client.send(formPost("/login",
                "username", email,
                "password", password,
                "_csrf", csrf), HttpResponse.BodyHandlers.ofString());
        assertRedirectStatus(response.statusCode());
        if (successful) {
            assertTrue(!response.headers().firstValue("location").orElse("").contains("error"),
                    "Sign in failed with redirect " + response.headers().firstValue("location").orElse("missing"));
            CookieManager cookieManager = (CookieManager) client.cookieHandler().orElseThrow();
            assertTrue(!cookieManager.getCookieStore().get(uri("/login")).isEmpty(),
                    "Successful sign in did not retain a browser session cookie");
        }
        return response;
    }

    private HttpResponse<String> authorize(HttpClient client, String organizationId, String verifier, String challenge)
            throws Exception {
        return authorizeWithMethod(client, organizationId, verifier, challenge, "S256", REDIRECT_URI);
    }

    private HttpResponse<String> authorizeWithReauthentication(HttpClient client, String organizationId,
            String verifier, String challenge) throws Exception {
        String path = "/oauth2/authorize?response_type=code"
                + "&client_id=" + enc(CLIENT_ID)
                + "&redirect_uri=" + enc(REDIRECT_URI)
                + "&scope=agentshield.api&state=" + UUID.randomUUID()
                + "&organization_id=" + enc(organizationId)
                + "&code_challenge=" + enc(challenge)
                + "&code_challenge_method=S256&reauthenticate=true";
        return client.send(HttpRequest.newBuilder(uri(path)).GET().build(), HttpResponse.BodyHandlers.ofString());
    }

    private HttpResponse<String> authorizeWithMethod(
            HttpClient client, String organizationId, String verifier, String challenge, String method,
            String redirectUri) throws Exception {
        StringBuilder path = new StringBuilder("/oauth2/authorize?response_type=code")
                .append("&client_id=").append(enc(CLIENT_ID))
                .append("&redirect_uri=").append(enc(redirectUri))
                .append("&scope=agentshield.api&state=").append(UUID.randomUUID())
                .append("&organization_id=").append(enc(organizationId));
        if (challenge != null) {
            path.append("&code_challenge=").append(enc(challenge))
                    .append("&code_challenge_method=").append(enc(method));
        }
        return client.send(HttpRequest.newBuilder(uri(path.toString())).GET().build(),
                HttpResponse.BodyHandlers.ofString());
    }

    private static String signJwt(
            java.security.PrivateKey privateKey, String keyId, JWSAlgorithm algorithm, String issuer,
            String audience, Instant expiresAt, String userId, String organizationId, String role) throws Exception {
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .issuer(issuer)
                .audience(audience)
                .subject(userId)
                .issueTime(java.util.Date.from(Instant.now().minusSeconds(1)))
                .notBeforeTime(java.util.Date.from(Instant.now().minusSeconds(1)))
                .expirationTime(java.util.Date.from(expiresAt))
                .claim("user_id", userId)
                .claim("organization_id", organizationId)
                .claim("organization_role", role)
                .build();
        JWSHeader.Builder header = new JWSHeader.Builder(algorithm);
        if (keyId != null) {
            header.keyID(keyId);
        }
        SignedJWT signed = new SignedJWT(header.build(), claims);
        if (JWSAlgorithm.RS256.equals(algorithm)) {
            signed.sign(new RSASSASigner((RSAPrivateKey) privateKey));
        } else {
            signed.sign(new MACSigner("hmac-key-for-negative-jwt-algorithm-test-0001"));
        }
        return signed.serialize();
    }

    private HttpRequest formPost(String path, String... nameValues) {
        StringBuilder form = new StringBuilder();
        for (int index = 0; index < nameValues.length; index += 2) {
            if (!form.isEmpty()) {
                form.append('&');
            }
            form.append(enc(nameValues[index])).append('=').append(enc(nameValues[index + 1]));
        }
        return HttpRequest.newBuilder(uri(path))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString(form.toString()))
                .build();
    }

    private static HttpClient newHttpClient() {
        CookieManager cookies = new CookieManager(null, CookiePolicy.ACCEPT_ALL);
        return HttpClient.newBuilder().cookieHandler(cookies).followRedirects(HttpClient.Redirect.NEVER).build();
    }

    private static String csrfCookie(HttpClient client) {
        CookieManager cookieManager = (CookieManager) client.cookieHandler().orElseThrow();
        return cookieManager.getCookieStore().get(URI.create("http://localhost/")).stream()
                .filter(cookie -> "XSRF-TOKEN".equals(cookie.getName()))
                .map(java.net.HttpCookie::getValue)
                .map(value -> java.net.URLDecoder.decode(value, StandardCharsets.UTF_8))
                .findFirst().orElse(null);
    }

    private static void assertRedirectStatus(int statusCode) {
        assertTrue(statusCode == 302 || statusCode == 303,
                "Expected a standard form-login redirect but received HTTP " + statusCode);
    }

    private URI uri(String path) {
        return URI.create("http://localhost:" + port + path);
    }

    private static String challenge(String verifier) throws Exception {
        byte[] digest = MessageDigest.getInstance("SHA-256").digest(verifier.getBytes(StandardCharsets.US_ASCII));
        return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
    }

    private static String queryParameter(String location, String name) {
        URI uri = URI.create(location);
        String query = uri.getRawQuery();
        if (query == null) {
            return null;
        }
        for (String pair : query.split("&")) {
            String[] parts = pair.split("=", 2);
            if (java.net.URLDecoder.decode(parts[0], StandardCharsets.UTF_8).equals(name)) {
                return java.net.URLDecoder.decode(parts.length == 2 ? parts[1] : "", StandardCharsets.UTF_8);
            }
        }
        return null;
    }

    private static String enc(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }

    private static String match(Pattern pattern, String value) {
        Matcher matcher = pattern.matcher(value);
        return matcher.find() ? matcher.group(1) : null;
    }
}
