package com.agentshield.runtimesecurity.runtime.integration;

public interface GatewayServiceTokenProvider {
    String tokenFor(String scope);
}
