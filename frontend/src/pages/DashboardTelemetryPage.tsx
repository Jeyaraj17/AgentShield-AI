import { useCallback, useEffect, useState } from 'react';
import { Activity, AlertTriangle, Gauge, LockKeyhole, RefreshCw, ShieldAlert, Sparkles } from 'lucide-react';
import { EmptyState, ErrorState, LoadingState, PageHeading, StatusBadge } from '../components/UI';
import { api } from '../lib/api';
import { useAuth } from '../context/auth-context';
import type { AnalysisFinding, DashboardPage as PageData, DriftHistoryItem, ExecutionHistoryItem, TrustScoreHistoryItem } from '../types';

type TelemetryPage = 'runtime' | 'analysis' | 'trust';
const pageCopy = {
  runtime: { icon: Activity, eyebrow: 'ENFORCEMENT TELEMETRY', title: 'Runtime monitoring', description: 'Organization-scoped policy decisions and protected tool execution outcomes.' },
  analysis: { icon: Sparkles, eyebrow: 'RISK INTELLIGENCE', title: 'AI analysis', description: 'Advisory prompt, response, hallucination, drift, and safety findings.' },
  trust: { icon: Gauge, eyebrow: 'POSTURE & RISK', title: 'Trust & risk', description: 'Explainable agent trust snapshots and historical risk and drift observations.' },
} as const;

export function DashboardTelemetryPage({ page }: { page: TelemetryPage }) {
  const { session } = useAuth();
  const [pageIndex, setPageIndex] = useState(0);
  const [busy, setBusy] = useState(true);
  const [error, setError] = useState('');
  const [executions, setExecutions] = useState<PageData<ExecutionHistoryItem> | null>(null);
  const [findings, setFindings] = useState<PageData<AnalysisFinding> | null>(null);
  const [risks, setRisks] = useState<PageData<AnalysisFinding> | null>(null);
  const [drifts, setDrifts] = useState<PageData<DriftHistoryItem> | null>(null);
  const [scores, setScores] = useState<PageData<TrustScoreHistoryItem> | null>(null);
  const [outcome, setOutcome] = useState('');
  const [category, setCategory] = useState('');
  const [severity, setSeverity] = useState('');
  const [agentId, setAgentId] = useState('');
  const [fromDate, setFromDate] = useState('');
  const [toDate, setToDate] = useState('');
  const [expanded, setExpanded] = useState<string | null>(null);
  const [detail, setDetail] = useState<ExecutionHistoryItem | null>(null);
  const isManager = session?.claims.organization_role === 'OWNER' || session?.claims.organization_role === 'ADMIN';
  const copy = pageCopy[page];

  const load = useCallback(async () => {
    if (!session || !isManager) { setBusy(false); return; }
    setBusy(true); setError('');
    const dateFilters = { from: fromDate ? new Date(`${fromDate}T00:00:00Z`).toISOString() : undefined,
      to: toDate ? new Date(`${toDate}T23:59:59.999Z`).toISOString() : undefined };
    try {
      if (page === 'runtime') {
        const value = await api.runtimeHistory({ page: pageIndex, size: 10, agentId: agentId.trim() || undefined, outcome: outcome || undefined, ...dateFilters });
        setExecutions(value);
      } else if (page === 'analysis') {
        const [findingData, riskData, driftData] = await Promise.all([
          api.analysisFindings({ page: pageIndex, size: 10, category: category || undefined, severity: severity || undefined, ...dateFilters }),
          api.riskHistory({ page: pageIndex, size: 10, ...dateFilters }), api.driftHistory({ page: pageIndex, size: 10, ...dateFilters }),
        ]);
        setFindings(findingData); setRisks(riskData); setDrifts(driftData);
      } else {
        const [scoreData, riskData, driftData] = await Promise.all([
          api.trustHistory({ page: pageIndex, size: 10, ...dateFilters }), api.riskHistory({ page: pageIndex, size: 10, ...dateFilters }), api.driftHistory({ page: pageIndex, size: 10, ...dateFilters }),
        ]);
        setScores(scoreData); setRisks(riskData); setDrifts(driftData);
      }
    } catch (reason) { setError(reason instanceof Error ? reason.message : 'Dashboard telemetry could not be loaded.'); }
    finally { setBusy(false); }
  }, [session, isManager, page, pageIndex, agentId, outcome, category, severity, fromDate, toDate]);
  useEffect(() => { void load(); }, [load]);

  const openExecution = async (id: string) => {
    setExpanded(id); setDetail(null);
    try { setDetail(await api.runtimeExecution(id)); }
    catch (reason) { setError(reason instanceof Error ? reason.message : 'Execution detail is unavailable.'); }
  };
  const pager = (value: { page: number; totalPages: number } | null) => <div className="table-pagination">
    <button className="button button-secondary" disabled={!value || value.page <= 0 || busy} onClick={() => setPageIndex((v) => Math.max(v - 1, 0))}>Previous</button>
    <span>{value ? `Page ${value.page + 1} of ${Math.max(value.totalPages, 1)}` : 'Page —'}</span>
    <button className="button button-secondary" disabled={!value || value.page + 1 >= value.totalPages || busy} onClick={() => setPageIndex((v) => v + 1)}>Next</button>
  </div>;

  if (!isManager) return <div className="page-stack"><PageHeading eyebrow={copy.eyebrow} title={copy.title} description={copy.description} /><section className="panel"><EmptyState title="Restricted dashboard telemetry" body="Runtime and AI risk histories are limited to organization OWNER and ADMIN roles. This view does not request or display organization telemetry for your role." /></section></div>;

  return <div className="page-stack">
    <PageHeading eyebrow={copy.eyebrow} title={copy.title} description={copy.description} actions={<button className="button button-secondary" onClick={() => void load()} disabled={busy}><RefreshCw size={15} />Refresh</button>} />
    {(page === 'runtime' || page === 'analysis' || page === 'trust') && <section className="panel telemetry-filters"><label>From date<input type="date" value={fromDate} onChange={(event) => { setFromDate(event.target.value); setPageIndex(0); }} /></label><label>To date<input type="date" value={toDate} onChange={(event) => { setToDate(event.target.value); setPageIndex(0); }} /></label>
      {page === 'runtime' && <><label>Execution outcome<select value={outcome} onChange={(event) => { setOutcome(event.target.value); setPageIndex(0); }}><option value="">All outcomes</option><option>PENDING</option><option>SUCCEEDED</option><option>FAILED</option><option>NOT_EXECUTED</option></select></label><label>Agent ID<input value={agentId} onChange={(event) => { setAgentId(event.target.value); setPageIndex(0); }} placeholder="Filter by agent UUID" /></label><span className="filter-note">Policy decision and execution outcome are separate fields.</span></>}
      {page === 'analysis' && <><label>Finding type<select value={category} onChange={(event) => { setCategory(event.target.value); setPageIndex(0); }}><option value="">All finding types</option><option>PROMPT</option><option>RESPONSE</option><option>HALLUCINATION</option></select></label><label>Severity<select value={severity} onChange={(event) => { setSeverity(event.target.value); setPageIndex(0); }}><option value="">All severities</option><option>LOW</option><option>MEDIUM</option><option>HIGH</option><option>CRITICAL</option></select></label></>}</section>}
    <div className="integration-note"><ShieldAlert size={16} /><span>AI findings and trust scores are advisory. Authorization decisions remain exclusively with the Policy Engine.</span></div>
    {busy ? <LoadingState label="Loading tenant-scoped telemetry" /> : error ? <ErrorState message={error} onRetry={() => void load()} /> : page === 'runtime' ? <section className="panel"><div className="panel-heading"><div><div className="eyebrow">POLICY DECISIONS & TOOL OUTCOMES</div><h2>Recent executions</h2></div><span className="tag tag-muted">{executions?.totalElements ?? 0} records</span></div>{executions?.content.length ? <><div className="table-scroll"><table className="data-table"><thead><tr><th>Agent / tool</th><th>Policy decision</th><th>Execution outcome</th><th>Resource</th><th>Completed</th></tr></thead><tbody>{executions.content.map((item) => <tr key={item.executionId}><td><div className="telemetry-primary"><button className="text-button" onClick={() => void openExecution(item.executionId)}>{item.tool}</button><small>{item.agentId}</small></div></td><td><StatusBadge status={item.policyDecision} /><small className="telemetry-reason">{item.reasonCode}</small></td><td><StatusBadge status={item.executionOutcome} /></td><td><code>{item.resource}</code></td><td>{item.completedAt ? new Date(item.completedAt).toLocaleString() : 'In progress'}</td></tr>)}</tbody></table></div>{expanded && <div className="telemetry-detail"><strong>Execution detail</strong>{detail?.executionId === expanded ? <><span>ID: {detail.executionId}</span><span>Correlation: {detail.correlationId}</span><span>Requested: {new Date(detail.requestedAt).toLocaleString()}</span></> : <span>Loading execution detail…</span>}<button className="button button-ghost" onClick={() => { setExpanded(null); setDetail(null); }}>Close</button></div>}{pager(executions)}</> : <EmptyState title="No runtime executions" body="No execution records match the current filters." />}</section> : page === 'analysis' ? <>
      <section className="panel"><div className="panel-heading"><div><div className="eyebrow">ADVISORY FINDINGS</div><h2>Prompt, response & hallucination analysis</h2></div><Sparkles size={18} /></div>{findings?.content.length ? <div className="table-scroll"><table className="data-table"><thead><tr><th>Finding</th><th>Severity</th><th>Categories</th><th>Sensitive data</th><th>Assessment</th><th>Created</th></tr></thead><tbody>{findings.content.map((item) => <tr key={item.analysisId}><td><strong>{item.analysisType}</strong><small>{item.agentId}</small></td><td><StatusBadge status={item.severity} /> <span>{item.riskScore ?? '—'}</span></td><td>{item.categories.join(', ') || '—'}</td><td>{item.sensitiveFindings.length ? item.sensitiveFindings.map((finding) => `${finding.category} × ${finding.count}`).join(', ') : 'None detected'}</td><td>{item.explanation || [...item.supportedClaims, ...item.unsupportedClaims, ...item.conflictingClaims].join(' · ') || 'No explanation returned'}</td><td>{new Date(item.createdAt).toLocaleString()}</td></tr>)}</tbody></table></div> : <EmptyState title="No analysis findings" body="There are no findings matching the selected category and severity." />}{pager(findings)}</section>
      <section className="panel"><div className="panel-heading"><div><div className="eyebrow">BEHAVIORAL SIGNALS</div><h2>Drift observations</h2></div></div>{drifts?.content.length ? <div className="table-scroll"><table className="data-table"><thead><tr><th>Agent</th><th>Drift</th><th>Score</th><th>Tool calls</th><th>Observed</th></tr></thead><tbody>{drifts.content.map((item) => <tr key={item.observationId}><td><code>{item.agentId}</code></td><td><StatusBadge status={item.driftDetected ? 'DRIFT_DETECTED' : 'STABLE'} /></td><td>{item.driftScore}</td><td>{item.toolCallCount}</td><td>{new Date(item.createdAt).toLocaleString()}</td></tr>)}</tbody></table></div> : <EmptyState title="No behavior observations" body="Behavior telemetry has not been recorded for this organization." />}{pager(drifts)}</section>
      <p className="filter-note">Risk history records: {risks?.totalElements ?? 0}. Full raw prompts and sensitive values are not returned.</p>
    </> : <>
      <section className="panel"><div className="panel-heading"><div><div className="eyebrow">EXPLAINABLE ADVISORY SCORE</div><h2>Agent trust snapshots</h2></div><Gauge size={18} /></div>{scores?.content.length ? <><div className="trust-score-grid">{latestScores(scores.content).map((item) => { const trend=scores.content.filter((entry)=>entry.agentId===item.agentId).slice().reverse(); return <article className="trust-score-card" key={item.agentId}><span className="trust-score-number">{item.score}<small>/100</small></span><code>{item.agentId}</code><div className="trust-sparkline" role="img" aria-label={`Recent trust scores: ${trend.map((point)=>point.score).join(', ')}`}>
        {trend.map((point,index)=><span key={`${point.calculatedAt}-${index}`} title={`${point.score} · ${new Date(point.calculatedAt).toLocaleDateString()}`} style={{height:`${Math.max(point.score,3)}%`}} />)}</div><small className="trust-explanation">Recent history from the current page</small><div className="trust-factor-list">{Object.entries(item.factors).map(([factor, value]) => <div key={factor}><span>{factor.replaceAll(/([A-Z])/g, ' $1')}</span><strong>{value}</strong></div>)}</div>{Object.values(item.explanations).map((explanation) => <p className="trust-explanation" key={explanation}>{explanation}</p>)}</article>; })}</div>{pager(scores)}</> : <EmptyState title="No trust score history" body="Trust snapshots appear after analysis or behavior observations are recorded." />}</section>
      <section className="panel"><div className="panel-heading"><div><div className="eyebrow">RISK & DRIFT HISTORY</div><h2>Recent risk signals</h2></div><AlertTriangle size={18} /></div>{risks?.content.length || drifts?.content.length ? <div className="table-scroll"><table className="data-table"><thead><tr><th>Agent</th><th>Signal</th><th>Risk / drift score</th><th>Recorded</th></tr></thead><tbody>{(risks?.content ?? []).map((item) => <tr key={item.analysisId}><td><code>{item.agentId}</code></td><td><StatusBadge status={item.analysisType} /></td><td>{item.riskScore ?? '—'}</td><td>{new Date(item.createdAt).toLocaleString()}</td></tr>)}{(drifts?.content ?? []).map((item) => <tr key={item.observationId}><td><code>{item.agentId}</code></td><td><StatusBadge status={item.driftDetected ? 'DRIFT_DETECTED' : 'DRIFT_STABLE'} /></td><td>{item.driftScore}</td><td>{new Date(item.createdAt).toLocaleString()}</td></tr>)}</tbody></table></div> : <EmptyState title="No risk history" body="There are no persisted risk or drift signals for this organization." />}</section>
      <div className="integration-note"><LockKeyhole size={16} /><span>Trust scoring is transparent and advisory. A low score cannot grant, deny, or override Policy Engine authorization.</span></div>
    </>}
  </div>;
}

function latestScores(items: TrustScoreHistoryItem[]) {
  const latest = new Map<string, TrustScoreHistoryItem>();
  items.forEach((item) => { if (!latest.has(item.agentId)) latest.set(item.agentId, item); });
  return [...latest.values()];
}
