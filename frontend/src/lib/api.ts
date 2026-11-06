import { getSession, logout, apiOrigin } from './auth';
import type { Agent, AgentPage, ApiProblem, CreateAgent, CurrentMembership, CurrentOrganization, OrganizationMember, OrganizationOnboardingRequest, OrganizationOnboardingResponse, Policy, PolicyDefinition, PolicyVersion, UserProfile, DashboardPage, ExecutionHistoryItem, AnalysisFinding, TrustScoreHistoryItem, DriftHistoryItem, AuditEvent, AuditSummary, Notification, SpringPage } from '../types';

export class ApiError extends Error {
  constructor(message: string, public readonly status: number) { super(message); this.name = 'ApiError'; }
}

async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  const token = getSession()?.accessToken;
  if (!token) throw new ApiError('Your session has ended. Sign in to continue.', 401);
  const headers = new Headers(init.headers);
  headers.set('Authorization', `Bearer ${token}`);
  headers.set('Accept', 'application/json');
  headers.set('X-Correlation-ID', crypto.randomUUID());
  if (init.body && !headers.has('Content-Type')) headers.set('Content-Type', 'application/json');
  const response = await fetch(new URL(path, apiOrigin()), { ...init, headers, signal: init.signal ?? AbortSignal.timeout(15000) });
  if (response.status === 401) { logout(); window.dispatchEvent(new CustomEvent('agentshield:unauthorized')); }
  if (!response.ok) {
    const problem = await response.json().catch(() => ({})) as ApiProblem;
    throw new ApiError(problem.detail || problem.message || problem.title || `Request failed (${response.status}).`, response.status);
  }
  if (response.status === 204) return undefined as T;
  return response.json() as Promise<T>;
}

async function publicRequest<T>(path: string, body: unknown): Promise<T> {
  let response: Response;
  try {
    response = await fetch(new URL(path, apiOrigin()), {
      method: 'POST',
      headers: { Accept: 'application/json', 'Content-Type': 'application/json', 'X-Correlation-ID': crypto.randomUUID() },
      body: JSON.stringify(body),
      credentials: 'omit',
      cache: 'no-store',
      signal: AbortSignal.timeout(15000),
    });
  } catch {
    throw new ApiError('Identity Service could not be reached. Check the API Gateway URL and try again.', 0);
  }
  if (!response.ok) {
    const problem = await response.json().catch(() => ({})) as ApiProblem;
    const message = response.status === 429
      ? 'Too many onboarding attempts. Wait a little and try again.'
      : problem.detail || problem.message || problem.title || `Organization setup failed (${response.status}).`;
    throw new ApiError(message, response.status);
  }
  return response.json() as Promise<T>;
}

export const api = {
  async runtimeHistory(filters: { page?: number; size?: number; agentId?: string; outcome?: string; decision?: string; from?: string; to?: string } = {}) {
    const query = new URLSearchParams(); Object.entries(filters).forEach(([key, value]) => { if (value !== undefined && value !== '') query.set(key, String(value)); });
    return request<DashboardPage<ExecutionHistoryItem>>(`/api/v1/runtime/history?${query}`);
  },
  async runtimeExecution(id: string) { return request<ExecutionHistoryItem>(`/api/v1/runtime/history/${encodeURIComponent(id)}`); },
  async analysisFindings(filters: { page?: number; size?: number; category?: string; severity?: string; from?: string; to?: string } = {}) {
    const query = new URLSearchParams(); Object.entries(filters).forEach(([key, value]) => { if (value !== undefined && value !== '') query.set(key, String(value)); });
    return request<DashboardPage<AnalysisFinding>>(`/api/v1/analysis/findings?${query}`);
  },
  async riskHistory(filters: { page?: number; size?: number; from?: string; to?: string } = {}) {
    const query = new URLSearchParams(); Object.entries(filters).forEach(([key, value]) => { if (value !== undefined && value !== '') query.set(key, String(value)); });
    return request<DashboardPage<AnalysisFinding>>(`/api/v1/analysis/risk-history?${query}`);
  },
  async driftHistory(filters: { page?: number; size?: number; from?: string; to?: string } = {}) {
    const query = new URLSearchParams(); Object.entries(filters).forEach(([key, value]) => { if (value !== undefined && value !== '') query.set(key, String(value)); });
    return request<DashboardPage<DriftHistoryItem>>(`/api/v1/analysis/drift-history?${query}`);
  },
  async trustScores(filters: { page?: number; size?: number; from?: string; to?: string } = {}) {
    const query = new URLSearchParams(); Object.entries(filters).forEach(([key, value]) => { if (value !== undefined && value !== '') query.set(key, String(value)); });
    return request<DashboardPage<TrustScoreHistoryItem>>(`/api/v1/analysis/trust-scores?${query}`);
  },
  async trustHistory(filters: { page?: number; size?: number; from?: string; to?: string } = {}) {
    const query = new URLSearchParams(); Object.entries(filters).forEach(([key, value]) => { if (value !== undefined && value !== '') query.set(key, String(value)); });
    return request<DashboardPage<TrustScoreHistoryItem>>(`/api/v1/analysis/trust-history?${query}`);
  },
  async onboardOrganization(value: OrganizationOnboardingRequest) {
    return publicRequest<OrganizationOnboardingResponse>('/api/v1/onboarding/organizations', value);
  },
  async agents(page = 0, size = 100) { return request<AgentPage>(`/api/v1/agents?page=${page}&size=${size}`); },
  async agent(id: string) { return request<Agent>(`/api/v1/agents/${encodeURIComponent(id)}`); },
  async createAgent(value: CreateAgent) { return request<Agent>('/api/v1/agents', { method: 'POST', body: JSON.stringify(value) }); },
  async updateAgent(id: string, value: CreateAgent) { return request<Agent>(`/api/v1/agents/${encodeURIComponent(id)}`, { method: 'PUT', body: JSON.stringify(value) }); },
  async setAgentStatus(id: string, status: Agent['status']) { return request<Agent>(`/api/v1/agents/${encodeURIComponent(id)}/status`, { method: 'PATCH', body: JSON.stringify({ status }) }); },
  async deactivateAgent(id: string) { return request<void>(`/api/v1/agents/${encodeURIComponent(id)}`, { method: 'DELETE' }); },
  async policies() { return request<Policy[]>('/api/v1/policies'); },
  async policy(id: string) { return request<Policy>(`/api/v1/policies/${encodeURIComponent(id)}`); },
  async policyVersions(id: string) { return request<PolicyVersion[]>(`/api/v1/policies/${encodeURIComponent(id)}/versions`); },
  async createPolicy(value: PolicyDefinition) { return request<Policy>('/api/v1/policies', { method: 'POST', body: JSON.stringify(value) }); },
  async updatePolicy(id: string, value: PolicyDefinition) { return request<Policy>(`/api/v1/policies/${encodeURIComponent(id)}`, { method: 'PUT', body: JSON.stringify(value) }); },
  async setPolicyStatus(id: string, status: 'ACTIVE' | 'DISABLED') { return request<Policy>(`/api/v1/policies/${encodeURIComponent(id)}/status`, { method: 'PATCH', body: JSON.stringify({ status }) }); },
  async me() { return request<UserProfile>('/api/v1/users/me'); },
  async currentOrganization() { return request<CurrentOrganization>('/api/v1/organizations/current'); },
  async currentMembership() { return request<CurrentMembership>('/api/v1/users/me/membership'); },
  async organizationMembers() { return request<OrganizationMember[]>('/api/v1/organizations/current/members'); },
  async auditEvents(filters: { page?: number; size?: number; eventType?: string; agentId?: string; from?: string; to?: string; outcome?: string } = {}) {
    const query = new URLSearchParams(); Object.entries(filters).forEach(([key, value]) => { if (value !== undefined && value !== '') query.set(key, String(value)); });
    return request<SpringPage<AuditEvent>>(`/api/v1/audit/events?${query}`);
  },
  async auditEvent(id: string) { return request<AuditEvent>(`/api/v1/audit/events/${encodeURIComponent(id)}`); },
  async auditSummary() { return request<AuditSummary>('/api/v1/audit/summary'); },
  async notifications(filters: { page?: number; size?: number; category?: string; severity?: string; unread?: boolean; from?: string; to?: string } = {}) {
    const query = new URLSearchParams(); Object.entries(filters).forEach(([key, value]) => { if (value !== undefined && value !== '') query.set(key, String(value)); });
    return request<SpringPage<Notification>>(`/api/v1/notifications?${query}`);
  },
  async notification(id: string) { return request<Notification>(`/api/v1/notifications/${encodeURIComponent(id)}`); },
  async markNotificationRead(id: string) { return request<Notification>(`/api/v1/notifications/${encodeURIComponent(id)}/read`, { method: 'PATCH' }); },
  async markAllNotificationsRead() { return request<{ updated: number }>('/api/v1/notifications/read-all', { method: 'PATCH' }); },
};
