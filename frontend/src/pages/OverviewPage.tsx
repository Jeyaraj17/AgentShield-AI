import { useCallback, useEffect, useState } from 'react';
import { Activity, ArrowRight, Bot, Fingerprint, ShieldCheck, ShieldX, Sparkles, TrendingUp, TriangleAlert } from 'lucide-react';
import { Link } from 'react-router-dom';
import { api } from '../lib/api';
import type { AgentPage, Policy } from '../types';
import { EmptyState, ErrorState, LoadingState, MetricCard, PageHeading, StatusBadge, UnavailableState } from '../components/UI';

export function OverviewPage() {
  const [agents, setAgents] = useState<AgentPage | null>(null);
  const [policies, setPolicies] = useState<Policy[] | null>(null);
  const [agentsError, setAgentsError] = useState(''); const [policiesError, setPoliciesError] = useState('');
  const [loading, setLoading] = useState(true);
  const load = useCallback(async () => {
    setLoading(true); setAgentsError(''); setPoliciesError('');
    const [agentResult, policyResult] = await Promise.allSettled([api.agents(0, 100), api.policies()]);
    if (agentResult.status === 'fulfilled') setAgents(agentResult.value); else setAgentsError(agentResult.reason instanceof Error ? agentResult.reason.message : 'Agent service could not be reached.');
    if (policyResult.status === 'fulfilled') setPolicies(policyResult.value); else setPoliciesError(policyResult.reason instanceof Error ? policyResult.reason.message : 'Policy service could not be reached.');
    setLoading(false);
  }, []);
  useEffect(() => { void load(); }, [load]);
  const activeCount = agents && agents.totalPages <= 1 ? agents.content.filter((agent) => agent.status === 'ACTIVE').length : null;
  const activePolicies = policies?.filter((policy) => policy.status === 'ACTIVE').length;

  return <div className="page-stack">
    <PageHeading eyebrow="SECURITY OVERVIEW" title="Overview" description="A clear view of your AI security posture, grounded in connected platform data." actions={<span className="live-refresh"><i />Connected sources</span>} />
    <div className="overview-banner"><div className="banner-mark"><ShieldCheck size={21} /></div><div><strong>Deterministic authorization authority</strong><span>The Policy Engine is the final ALLOW / DENY authority. Live decision metrics are not routed to this console yet.</span></div><span className="banner-pill banner-pill-muted">POLICY ENGINE</span></div>
    {agentsError && <ErrorState message={agentsError} onRetry={() => void load()} />}
    {policiesError && <ErrorState message={policiesError} onRetry={() => void load()} />}
    <div className="metrics-grid">
      <MetricCard label="Registered agents" value={loading ? '—' : agents?.totalElements ?? '—'} note={agentsError ? 'Agent API unavailable' : 'Live from Agent Management'} icon={<Bot size={18} />} accent="blue" />
      <MetricCard label="Active agents" value={loading ? '—' : activeCount ?? '—'} note={activeCount === null ? 'Full active count needs aggregation' : 'Current organization'} icon={<Fingerprint size={18} />} accent="cyan" unavailable={activeCount === null && !loading} />
      <MetricCard label="Active policies" value={loading ? '—' : activePolicies ?? '—'} note={policiesError ? 'Policy API unavailable' : 'Live from Policy Engine'} icon={<ShieldCheck size={18} />} accent="violet" />
      <MetricCard label="Average trust score" value="—" note="AI Analysis route is unavailable" icon={<TrendingUp size={18} />} accent="green" unavailable />
      <MetricCard label="Threat detections" value="—" note="AI Analysis route is unavailable" icon={<TriangleAlert size={18} />} accent="amber" unavailable />
      <MetricCard label="ALLOW / DENY activity" value="— / —" note="Runtime and audit routes are unavailable" icon={<ShieldX size={18} />} accent="red" unavailable />
    </div>

    <div className="dashboard-grid dashboard-grid-main">
      <section className="panel chart-panel"><div className="panel-heading"><div><div className="eyebrow">SECURITY SIGNAL</div><h2>Trust score trend</h2></div><span className="tag tag-muted">No data</span></div><div className="chart-empty-wrap"><div className="chart-grid-lines"><span /><span /><span /><span /></div><div className="chart-empty-icon"><TrendingUp size={19} /></div><strong>No trust history available</strong><p>Trust score history is provided by AI Analysis, which is not exposed through the API Gateway yet.</p></div></section>
      <section className="panel risk-panel"><div className="panel-heading"><div><div className="eyebrow">THREAT LANDSCAPE</div><h2>Risk distribution</h2></div><span className="panel-kebab">···</span></div><div className="risk-empty"><div className="risk-donut"><div><TriangleAlert size={20} /><b>—</b><small>FINDINGS</small></div></div><p>Threat distribution will appear when AI Analysis events are routed to the console.</p></div><div className="risk-legend"><span><i className="legend-dot legend-critical" />Critical <b>—</b></span><span><i className="legend-dot legend-high" />High <b>—</b></span><span><i className="legend-dot legend-medium" />Medium <b>—</b></span><span><i className="legend-dot legend-low" />Low <b>—</b></span></div></section>
    </div>

    <div className="dashboard-grid dashboard-grid-bottom">
      <section className="panel table-panel"><div className="panel-heading"><div><div className="eyebrow">FLEET</div><h2>Recent agents</h2></div><Link className="text-link" to="/agents">View all <ArrowRight size={14} /></Link></div>
        {loading ? <LoadingState label="Loading agents" /> : agentsError ? <div className="panel-message">Agent list is unavailable.</div> : !agents?.content.length ? <EmptyState title="No agents registered" body="Register an agent to begin building your protected fleet." /> : <div className="table-scroll"><table><thead><tr><th>Agent</th><th>Type</th><th>Status</th><th>Capabilities</th></tr></thead><tbody>{agents.content.slice(0, 5).map((agent) => <tr key={agent.id}><td><div className="agent-cell"><span className="agent-avatar"><Bot size={16} /></span><span><strong>{agent.name}</strong><small>{agent.agentCode}</small></span></div></td><td>{agent.agentType}</td><td><StatusBadge status={agent.status} /></td><td><span className="cap-count">{agent.capabilities.length} capabilities</span></td></tr>)}</tbody></table></div>}
      </section>
      <section className="panel events-panel"><div className="panel-heading"><div><div className="eyebrow">ACTIVITY</div><h2>Recent security events</h2></div><span className="tag tag-muted">Unavailable</span></div><UnavailableState title="Audit feed not connected" detail="Audit Service has no API Gateway route. Events are not simulated or sampled in this dashboard." endpoint="GET /api/v1/audit/events" /></section>
    </div>
    <div className="source-note"><Activity size={14} /><span>Agent and policy totals are loaded from the authenticated organization. Unsupported security metrics are shown as unavailable.</span><Sparkles size={14} /></div>
  </div>;
}
