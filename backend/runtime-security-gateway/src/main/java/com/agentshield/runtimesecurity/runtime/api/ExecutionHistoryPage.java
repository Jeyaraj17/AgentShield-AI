package com.agentshield.runtimesecurity.runtime.api;

import java.util.List;
public record ExecutionHistoryPage(List<ExecutionHistoryItem> content, int page, int size, long totalElements, int totalPages) { }
