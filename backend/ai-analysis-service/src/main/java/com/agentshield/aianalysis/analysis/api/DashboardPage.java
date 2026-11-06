package com.agentshield.aianalysis.analysis.api;

import java.util.List;
public record DashboardPage<T>(List<T> content,int page,int size,long totalElements,int totalPages) { }
