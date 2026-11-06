export type UserRole = 'OWNER' | 'ADMIN' | 'MEMBER';
export interface UserClaims { sub: string; user_id: string; organization_id: string; organization_role: UserRole; exp: number; email?: string; }
export interface Agent {
  id: string; organizationId: string; name: string; agentCode: string; description: string | null;
  agentType: string; status: 'ACTIVE' | 'INACTIVE' | 'SUSPENDED'; capabilities: string[];
  createdAt: string; updatedAt: string;
}
export interface AgentPage { content: Agent[]; page: number; size: number; totalElements: number; totalPages: number; }
export interface CreateAgent { name: string; agentCode: string; description?: string; agentType: string; capabilities: string[]; }
export interface PolicyRule {
  id?: string; name: string; agentScope: 'ALL_AGENTS' | 'SPECIFIC_AGENT'; targetAgentId?: string | null;
  action: string; effect: 'ALLOW' | 'DENY'; conditions?: { join: 'ALL' | 'ANY'; clauses: Array<{ field: string; operator: string; value: unknown }> } | null;
  createdAt?: string;
}
export interface Policy {
  policyId: string; versionId: string; organizationId: string; name: string; description: string | null;
  version: number; status: 'DRAFT' | 'ACTIVE' | 'DISABLED'; priority: number;
  createdAt: string; updatedAt: string; rules: PolicyRule[];
}
export interface PolicyDefinition { name: string; description?: string; priority: number; rules: PolicyRule[]; }
export interface PolicyVersion { policyId: string; versionId: string; version: number; status: 'DRAFT' | 'ACTIVE' | 'DISABLED'; latest: boolean; createdAt: string; updatedAt: string; }
export interface UserProfile { id: string; email: string; firstName: string; lastName: string; status: string; }
export interface CurrentOrganization { id: string; name: string; organizationCode: string; status: 'ACTIVE' | 'INACTIVE'; }
export interface CurrentMembership { id: string; userId: string; organizationId: string; role: UserRole; status: 'ACTIVE' | 'INACTIVE'; joinedAt: string; }
export interface OrganizationMember {
  userId: string; email: string; firstName: string; lastName: string; accountStatus: string;
  role: UserRole; membershipStatus: 'ACTIVE' | 'INACTIVE'; joinedAt: string;
}
export interface ApiProblem { detail?: string; message?: string; title?: string; }
export interface DashboardPage<T> { content: T[]; page: number; size: number; totalElements: number; totalPages: number; }
export interface SpringPage<T> { content: T[]; page: number; size: number; totalElements: number; totalPages: number; }
export interface AuditEvent {
  eventId: string; eventType: string; actorIdentity: string; actorType: string; agentId: string | null; executionId: string | null;
  action: string | null; resource: string | null; decision: 'ALLOW' | 'DENY' | null; reason: string | null;
  executionOutcome: 'SUCCEEDED' | 'FAILED' | null; correlationId: string; eventTimestamp: string; receivedTimestamp: string;
}
export interface AuditSummary { totalEvents: number; authorizationAllow: number; authorizationDeny: number; executionSucceeded: number; executionFailed: number; aiThreats: number; }
export interface Notification {
  notificationId: string; category: string; severity: string; title: string; description: string; sourceEventType: string;
  agentId: string | null; executionId: string | null; sourceIdentifier: string | null; correlationId: string;
  eventTimestamp: string; createdAt: string; readAt: string | null;
}
export interface ExecutionHistoryItem {
  executionId: string; agentId: string; agentName: string | null; tool: string; resource: string;
  policyDecision: 'ALLOW' | 'DENY'; reasonCode: string; executionOutcome: string; correlationId: string;
  requestedAt: string; completedAt: string | null;
}
export interface AnalysisFinding {
  analysisId: string; agentId: string; analysisType: string; severity: string; riskScore: number | null;
  categories: string[]; sensitiveFindings: Array<{ category: string; count: number }>; explanation: string | null; supportedClaims: string[]; unsupportedClaims: string[];
  conflictingClaims: string[]; llmStatus: string | null; createdAt: string;
}
export interface TrustScoreHistoryItem {
  agentId: string; score: number; factors: Record<string, number>; explanations: Record<string, string>; calculatedAt: string;
}
export interface DriftHistoryItem {
  observationId: string; agentId?: string; toolCallCount: number; errorCount: number; driftScore: number;
  driftDetected: boolean; actionDistribution: Record<string, number>; createdAt: string;
}
export interface OrganizationOnboardingRequest { organizationName: string; firstName: string; lastName: string; email: string; password: string; }
export interface OrganizationOnboardingResponse { organizationId: string; }
