import { render, screen } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { DashboardTelemetryPage } from './DashboardTelemetryPage';

const { runtimeHistory, runtimeExecution, analysisFindings, riskHistory, driftHistory, trustHistory, authSession } = vi.hoisted(() => ({
  runtimeHistory: vi.fn(), runtimeExecution: vi.fn(), analysisFindings: vi.fn(), riskHistory: vi.fn(), driftHistory: vi.fn(), trustHistory: vi.fn(),
  authSession: { claims: { organization_role: 'OWNER' } },
}));
vi.mock('../lib/api', () => ({ api: { runtimeHistory, runtimeExecution, analysisFindings, riskHistory, driftHistory, trustHistory } }));
vi.mock('../context/auth-context', () => ({ useAuth: () => ({ session: authSession }) }));

describe('dashboard telemetry', () => {
  beforeEach(() => {
    authSession.claims.organization_role = 'OWNER';
    runtimeHistory.mockReset(); runtimeExecution.mockReset(); analysisFindings.mockReset(); riskHistory.mockReset(); driftHistory.mockReset(); trustHistory.mockReset();
    runtimeHistory.mockResolvedValue({ content: [{ executionId: 'exec-1', agentId: 'agent-1', agentName: null, tool: 'tool.read', resource: 'doc-1', policyDecision: 'DENY', reasonCode: 'NO_RULE', executionOutcome: 'NOT_EXECUTED', correlationId: 'corr-1', requestedAt: '2026-01-01T00:00:00Z', completedAt: '2026-01-01T00:00:01Z' }], page: 0, size: 10, totalElements: 1, totalPages: 1 });
    runtimeExecution.mockResolvedValue({ executionId: 'exec-1', agentId: 'agent-1', agentName: null, tool: 'tool.read', resource: 'doc-1', policyDecision: 'DENY', reasonCode: 'NO_RULE', executionOutcome: 'NOT_EXECUTED', correlationId: 'corr-1', requestedAt: '2026-01-01T00:00:00Z', completedAt: '2026-01-01T00:00:01Z' });
    analysisFindings.mockResolvedValue({ content: [], page: 0, size: 10, totalElements: 0, totalPages: 0 });
    riskHistory.mockResolvedValue({ content: [], page: 0, size: 10, totalElements: 0, totalPages: 0 });
    driftHistory.mockResolvedValue({ content: [], page: 0, size: 10, totalElements: 0, totalPages: 0 });
    trustHistory.mockResolvedValue({ content: [], page: 0, size: 10, totalElements: 0, totalPages: 0 });
  });

  it('renders real runtime decision separately from execution outcome', async () => {
    render(<DashboardTelemetryPage page="runtime" />);
    expect(await screen.findByText('NO_RULE')).toBeInTheDocument();
    expect(screen.getByText('NOT EXECUTED')).toBeInTheDocument();
    expect(runtimeHistory).toHaveBeenCalled();
  });

  it('shows a retryable error when dashboard data is unavailable', async () => {
    runtimeHistory.mockRejectedValue(new Error('Telemetry service unavailable'));
    render(<DashboardTelemetryPage page="runtime" />);
    expect(await screen.findByText('Telemetry service unavailable')).toBeInTheDocument();
  });

  it('does not request organization telemetry for a MEMBER', async () => {
    authSession.claims.organization_role = 'MEMBER';
    render(<DashboardTelemetryPage page="analysis" />);
    expect(await screen.findByText('Restricted dashboard telemetry')).toBeInTheDocument();
    expect(analysisFindings).not.toHaveBeenCalled();
  });
});
