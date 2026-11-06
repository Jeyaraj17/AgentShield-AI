package com.agentshield.identity.config;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.Base64;

import org.springframework.test.context.DynamicPropertyRegistry;

public final class TestKeyMaterial {

    private static final KeyPair KEY_PAIR = generateKeyPair();

    private TestKeyMaterial() { }

    public static void register(DynamicPropertyRegistry registry) {
        registry.add("agentshield.security.jwt.generate-ephemeral-key", () -> "false");
        registry.add("agentshield.security.jwt.private-key-base64", () -> Base64.getEncoder().encodeToString(
                KEY_PAIR.getPrivate().getEncoded()));
        registry.add("agentshield.security.jwt.public-key-base64", () -> Base64.getEncoder().encodeToString(
                KEY_PAIR.getPublic().getEncoded()));
        registry.add("agentshield.security.runtime-gateway.client-secret", () -> "test-only-runtime-gateway-secret");
        registry.add("agentshield.security.runtime-gateway.analysis-client-secret", () -> "test-only-runtime-gateway-analysis-secret");
        registry.add("agentshield.security.agent-management.base-url", () -> "https://agent-management.example.test");
    }

    public static KeyPair generateKeyPair() {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(2048);
            return generator.generateKeyPair();
        } catch (Exception exception) {
            throw new ExceptionInInitializerError(exception);
        }
    }

    public static KeyPair activeKeyPair() {
        return KEY_PAIR;
    }
}
