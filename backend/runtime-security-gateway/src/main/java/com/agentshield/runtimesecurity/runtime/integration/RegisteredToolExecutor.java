package com.agentshield.runtimesecurity.runtime.integration;

import java.util.Map;
import com.agentshield.runtimesecurity.runtime.api.RuntimeToolRequest;

public interface RegisteredToolExecutor {
    boolean isRegistered(String action);
    Map<String,Object> execute(RuntimeToolRequest request);
}
