package com.agentshield.identity.config;

import java.util.ArrayList;
import java.util.List;

import org.springframework.beans.factory.config.BeanFactoryPostProcessor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;

@Configuration
public class DatabaseConfiguration {

    @Bean
    static BeanFactoryPostProcessor validateDatabaseConfiguration(Environment environment) {
        return beanFactory -> {
            String jdbcUrl = environment.getProperty("spring.datasource.url", "");
            if (jdbcUrl.startsWith("jdbc:h2:")) {
                return;
            }

            List<String> missingVariables = new ArrayList<>();
            requireProperty(environment, "spring.datasource.url", "DB_URL", missingVariables);
            requireProperty(environment, "spring.datasource.username", "DB_USERNAME", missingVariables);
            requireProperty(environment, "spring.datasource.password", "DB_PASSWORD", missingVariables);

            if (!missingVariables.isEmpty()) {
                throw new IllegalStateException(
                        "Missing required database configuration: " + String.join(", ", missingVariables)
                                + ". Set these environment variables or configure them in an uncommitted local file.");
            }
        };
    }

    private static void requireProperty(
            Environment environment, String propertyName, String variableName, List<String> missingVariables) {
        if (environment.getProperty(propertyName, "").isBlank()) {
            missingVariables.add(variableName);
        }
    }
}
