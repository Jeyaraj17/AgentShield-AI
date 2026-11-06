package com.agentshield.identity.agentcredential.api;

import java.util.UUID;
import jakarta.validation.constraints.NotNull;

public record IssueAgentCredentialRequest(@NotNull UUID agentId) { }
