import { useCallback, useEffect, useMemo, useState, type FormEvent } from 'react';
import { Bot, ChevronLeft, ChevronRight, Eye, Filter, MoreHorizontal, Pencil, RefreshCw, Search, ShieldCheck, Trash2, X } from 'lucide-react';
import { api } from '../lib/api';
import { useAuth } from '../context/auth-context';
import type { Agent, AgentPage, CreateAgent } from '../types';
import { AddButton, Button, EmptyState, ErrorState, FormField, LoadingState, Modal, PageHeading, StatusBadge } from '../components/UI';

export function AgentsPage() {
  const { session } = useAuth(); const canManage = session?.claims.organization_role !== 'MEMBER';
  const [page, setPage] = useState(0); const [data, setData] = useState<AgentPage | null>(null); const [loading, setLoading] = useState(true); const [error, setError] = useState('');
  const [query, setQuery] = useState(''); const [status, setStatus] = useState('ALL'); const [modal, setModal] = useState(false); const [editing, setEditing] = useState<Agent | null>(null);
  const [selected, setSelected] = useState<Agent | null>(null); const [detailLoading, setDetailLoading] = useState(false); const [notice, setNotice] = useState('');
  const load = useCallback(async () => {
    setLoading(true); setError('');
    try { setData(await api.agents(page, 20)); } catch (reason) { setError(reason instanceof Error ? reason.message : 'Agent Management is unavailable.'); }
    finally { setLoading(false); }
  }, [page]);
  useEffect(() => { void load(); }, [load]);
  const filtered = useMemo(() => (data?.content ?? []).filter((agent) => {
    const search = `${agent.name} ${agent.agentCode} ${agent.agentType} ${agent.capabilities.join(' ')}`.toLowerCase();
    return search.includes(query.toLowerCase()) && (status === 'ALL' || agent.status === status);
  }), [data, query, status]);
  async function showDetails(agent: Agent) {
    setSelected(agent); setDetailLoading(true);
    try { setSelected(await api.agent(agent.id)); } catch (reason) { setNotice(reason instanceof Error ? reason.message : 'Agent details could not be loaded.'); }
    finally { setDetailLoading(false); }
  }
  function openCreate() { setEditing(null); setModal(true); }
  function openEdit(agent: Agent) { setEditing(agent); setSelected(null); setModal(true); }
  async function changeStatus(agent: Agent, next: Agent['status']) {
    try { await api.setAgentStatus(agent.id, next); setNotice(`${agent.name} status updated.`); await load(); if (selected?.id === agent.id) setSelected({ ...agent, status: next }); }
    catch (reason) { setNotice(reason instanceof Error ? reason.message : 'Status update failed.'); }
  }
  async function deactivate(agent: Agent) {
    if (!window.confirm(`Deactivate ${agent.name}? The agent record and its history will be retained.`)) return;
    try { await api.deactivateAgent(agent.id); setNotice(`${agent.name} deactivated.`); setSelected(null); await load(); }
    catch (reason) { setNotice(reason instanceof Error ? reason.message : 'Deactivation failed.'); }
  }
  async function save(event: FormEvent<HTMLFormElement>) {
    event.preventDefault(); const form = new FormData(event.currentTarget);
    const payload: CreateAgent = { name: String(form.get('name')).trim(), agentCode: String(form.get('agentCode')).trim(), description: String(form.get('description')).trim(), agentType: String(form.get('agentType')).trim(), capabilities: String(form.get('capabilities')).split(/[\n,]/).map((value) => value.trim()).filter(Boolean) };
    try {
      if (editing) await api.updateAgent(editing.id, payload); else await api.createAgent(payload);
      setNotice(editing ? 'Agent details saved as current state.' : 'Agent registered successfully.'); setModal(false); await load();
    } catch (reason) { setNotice(reason instanceof Error ? reason.message : 'The agent could not be saved.'); }
  }

  return <div className="page-stack">
    <PageHeading eyebrow="AGENT INVENTORY" title="AI Agents" description="Register, inspect, and manage the agents operating in your organization." actions={canManage && <AddButton onClick={openCreate}>Register agent</AddButton>} />
    {notice && <div className="inline-notice" role="status"><span>{notice}</span><button aria-label="Dismiss notification" onClick={() => setNotice('')}><X size={15} /></button></div>}
    <div className="inventory-summary"><div><span className="inventory-icon"><Bot size={18} /></span><div><strong>{data?.totalElements ?? '—'}</strong><small>registered agents</small></div></div><div className="summary-divider" /><div><span className="summary-dot summary-active" /><div><strong>{data?.content.filter((agent) => agent.status === 'ACTIVE').length ?? '—'}</strong><small>active on this page</small></div></div><span className="inventory-live"><i />Connected to Agent Management</span></div>
    <section className="panel inventory-panel"><div className="inventory-toolbar"><div className="search-control"><Search size={16} /><input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search this page by name, code, capability…" aria-label="Search agents on this page" /></div><div className="toolbar-filters"><span className="filter-icon"><Filter size={15} /></span><select value={status} onChange={(event) => setStatus(event.target.value)} aria-label="Filter by agent status"><option value="ALL">All statuses</option><option value="ACTIVE">Active</option><option value="INACTIVE">Inactive</option><option value="SUSPENDED">Suspended</option></select><button className="icon-button" aria-label="Refresh agents" onClick={() => void load()}><RefreshCw size={16} /></button></div></div>
      {loading ? <LoadingState label="Loading registered agents" /> : error ? <ErrorState message={error} onRetry={() => void load()} /> : <div className="table-scroll"><table className="data-table"><thead><tr><th>Agent</th><th>Type</th><th>Status</th><th>Capabilities</th><th>Last updated</th><th><span className="sr-only">Actions</span></th></tr></thead><tbody>
        {filtered.map((agent) => <tr key={agent.id}><td><button className="agent-cell agent-row-button" onClick={() => void showDetails(agent)}><span className="agent-avatar"><Bot size={16} /></span><span><strong>{agent.name}</strong><small>{agent.agentCode}</small></span></button></td><td><span className="type-label">{agent.agentType}</span></td><td><StatusBadge status={agent.status} /></td><td><div className="capability-list">{agent.capabilities.slice(0, 2).map((capability) => <span key={capability}>{capability}</span>)}{agent.capabilities.length > 2 && <span className="cap-more">+{agent.capabilities.length - 2}</span>}{agent.capabilities.length === 0 && <span className="cap-empty">No capabilities</span>}</div></td><td><span className="date-cell">{new Date(agent.updatedAt).toLocaleDateString(undefined, { month: 'short', day: 'numeric', year: 'numeric' })}</span></td><td><div className="row-actions"><button className="icon-button" aria-label={`View ${agent.name}`} onClick={() => void showDetails(agent)}><Eye size={16} /></button>{canManage && <button className="icon-button" aria-label={`Edit ${agent.name}`} onClick={() => openEdit(agent)}><Pencil size={15} /></button>}<button className="icon-button" aria-label={`More about ${agent.name}`} onClick={() => void showDetails(agent)}><MoreHorizontal size={17} /></button></div></td></tr>)}
        {!filtered.length && <tr><td colSpan={6}><EmptyState title={data?.content.length ? 'No matching agents' : 'Your agent inventory is empty'} body={data?.content.length ? 'Try a different search or status filter.' : 'Register an AI agent to make it visible in this organization.'} action={canManage && !data?.content.length && <AddButton onClick={openCreate}>Register first agent</AddButton>} /></td></tr>}
      </tbody></table></div>}
      <div className="table-pagination"><span>Page {data ? data.page + 1 : 1} of {data?.totalPages || 1} <small>· {data?.totalElements ?? 0} agents total</small></span><div><Button variant="secondary" aria-label="Previous page" disabled={!data || data.page <= 0 || loading} onClick={() => setPage(Math.max(0, page - 1))}><ChevronLeft size={15} />Previous</Button><Button variant="secondary" aria-label="Next page" disabled={!data || data.page + 1 >= data.totalPages || loading} onClick={() => setPage(page + 1)}>Next<ChevronRight size={15} /></Button></div></div>
    </section>
    {modal && <Modal wide title={editing ? 'Update agent' : 'Register an agent'} subtitle={editing ? 'Changes update this organization-scoped agent record.' : 'Register a trusted agent profile and its declared capabilities.'} onClose={() => setModal(false)}><form className="form-grid" onSubmit={(event) => void save(event)}>
      <FormField label="Agent name"><input name="name" required maxLength={150} defaultValue={editing?.name ?? ''} placeholder="e.g. Support operations assistant" /></FormField>
      <FormField label="Agent code" hint="Unique within this organization."><input name="agentCode" required maxLength={50} pattern="[A-Za-z0-9][A-Za-z0-9._-]{0,49}" defaultValue={editing?.agentCode ?? ''} placeholder="SUPPORT-OPS" /></FormField>
      <FormField label="Agent type"><input name="agentType" required maxLength={50} defaultValue={editing?.agentType ?? 'ASSISTANT'} placeholder="ASSISTANT" /></FormField>
      <FormField label="Capabilities" hint="One capability per line or comma-separated."><textarea name="capabilities" rows={3} maxLength={3000} defaultValue={editing?.capabilities.join('\n') ?? ''} placeholder={'ticket.read\nknowledge.search'} /></FormField>
      <div className="form-span"><FormField label="Description"><textarea name="description" rows={2} maxLength={1000} defaultValue={editing?.description ?? ''} placeholder="What is this agent responsible for?" /></FormField></div>
      <div className="form-footer form-span"><Button type="button" variant="secondary" onClick={() => setModal(false)}>Cancel</Button><Button type="submit">{editing ? 'Save changes' : 'Register agent'}</Button></div>
    </form></Modal>}
    {selected && <div className="drawer-backdrop" onMouseDown={(event) => { if (event.currentTarget === event.target) setSelected(null); }}><aside className="detail-drawer" aria-label="Agent details"><div className="drawer-heading"><span className="agent-avatar agent-avatar-large"><Bot size={21} /></span><button className="icon-button" aria-label="Close agent details" onClick={() => setSelected(null)}><X size={18} /></button></div>{detailLoading ? <LoadingState label="Loading agent details" /> : <><div className="drawer-title-row"><div><div className="eyebrow">AGENT PROFILE</div><h2>{selected.name}</h2><span className="agent-code">{selected.agentCode}</span></div><StatusBadge status={selected.status} /></div><p className="drawer-description">{selected.description || 'No description has been added.'}</p><div className="detail-block"><div className="detail-label">Agent type</div><strong>{selected.agentType}</strong></div><div className="detail-block"><div className="detail-label">Declared capabilities <span>{selected.capabilities.length}</span></div><div className="detail-capabilities">{selected.capabilities.length ? selected.capabilities.map((capability) => <span key={capability}><ShieldCheck size={13} />{capability}</span>) : <small>No capabilities registered</small>}</div></div><div className="detail-meta"><span>Registered <b>{new Date(selected.createdAt).toLocaleString()}</b></span><span>Updated <b>{new Date(selected.updatedAt).toLocaleString()}</b></span><span>Agent ID <code>{selected.id}</code></span></div>{canManage && <div className="drawer-actions"><Button variant="secondary" onClick={() => openEdit(selected)}><Pencil size={15} />Edit details</Button><label className="select-status"><span className="sr-only">Change status</span><select value={selected.status} onChange={(event) => void changeStatus(selected, event.target.value as Agent['status'])}><option value="ACTIVE">ACTIVE</option><option value="INACTIVE">INACTIVE</option><option value="SUSPENDED">SUSPENDED</option></select></label><Button variant="danger" onClick={() => void deactivate(selected)} disabled={selected.status === 'INACTIVE'}><Trash2 size={15} />Deactivate</Button></div>}</>}</aside></div>}
  </div>;
}
