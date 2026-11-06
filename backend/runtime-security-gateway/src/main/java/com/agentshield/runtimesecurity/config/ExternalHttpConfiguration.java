package com.agentshield.runtimesecurity.config;

import java.net.http.HttpClient;
import java.time.Duration;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.client.ClientHttpRequestFactory;
import org.springframework.http.client.JdkClientHttpRequestFactory;

@Configuration
public class ExternalHttpConfiguration {
    @Bean ClientHttpRequestFactory externalRequestFactory(
            @Value("${agentshield.http.connect-timeout}") Duration connectTimeout,
            @Value("${agentshield.http.response-timeout}") Duration responseTimeout) {
        JdkClientHttpRequestFactory factory=new JdkClientHttpRequestFactory(HttpClient.newBuilder()
                .connectTimeout(connectTimeout).followRedirects(HttpClient.Redirect.NEVER).build());
        factory.setReadTimeout(responseTimeout);
        return factory;
    }
}
