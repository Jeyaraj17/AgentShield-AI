import { useCallback, useEffect, useState, type FormEvent } from 'react';
import { FileClock, GitBranch, Plus, RefreshCw, Shield, ShieldAlert, ShieldCheck, X } from 'lucide-react';
import { api } from '../lib/api';
import { useAuth } from '../context/auth-context';
import type { Policy, PolicyDefinition, PolicyRule, PolicyVersion } from '../types';
import { AddButton, Button, EmptyState, ErrorState, FormField, LoadingState, Modal, PageHeading, StatusBadge } from '../components/UI';

interface RuleInput { name: string; agentScope: 'ALL_AGENTS' | 'SPECIFIC_AGENT'; targetAgentId: string; action: string; effect: 'ALLOW' | 'DENY'; conditionJson: string; }
const blankRule: RuleInput = { name: '', agentScope: 'ALL_AGENTS', targetAgentId: '', action: '', effect: 'ALLOW', conditionJson: '' };

export function PoliciesPage() {
  const { session } = useAuth(); const canManage = session?.claims.organization_role !== 'MEMBER';
  const [policies, setPolicies] = useState<Policy[]>([]); const [loading, setLoading] = useState(true); const [error, setError] = useState('');
  const [modal, setModal] = useState(false); const [editing, setEditing] = useState<Policy | null>(null); const [selected, setSelected] = useState<Policy | null>(null);
  const [versions, setVersions] = useState<PolicyVersion[]>([]); const [versionLoading, setVersionLoading] = useState(false); const [notice, setNotice] = useState(''); const [filter, setFilter] = useState('ALL');
  const load = useCallback(async () => { setLoading(true); setError(''); try { setPolicies(await api.policies()); } catch (reason) { setError(reason instanceof Error ? reason.message : 'Policy Engine is unavailable.'); } finally { setLoading(false); } }, []);
  useEffect(() => { void load(); }, [load]);
  const visible = filter === 'ALL' ? policies : policies.filter((policy) => policy.status === filter);
  function openCreate() { setEditing(null); setModal(true); }
  function openEdit(policy: Policy) { setEditing(policy); setSelected(null); setModal(true); }
  async function showPolicy(policy: Policy) {
    setSelected(policy); setVersions([]); setVersionLoading(true);
    try { setVersions(await api.policyVersions(policy.policyId)); } catch (reason) { setNotice(reason instanceof Error ? reason.message : 'Version history is unavailable.'); }
    finally { setVersionLoading(false); }
  }
  async function statusChange(policy: Policy, status: 'ACTIVE' | 'DISABLED') {
    try { await api.setPolicyStatus(policy.policyId, status); setNotice(`Policy ${status.toLowerCase()}.`); setSelected(null); await load(); }
    catch (reason) { setNotice(reason instanceof Error ? reason.message : 'Policy status could not be changed.'); }
  }
  async function save(event: FormEvent<HTMLFormElement>) {
    event.preventDefault(); const form = new FormData(event.currentTarget);
    try {
      const rules: PolicyRule[] = (form.getAll('ruleName') as string[]).map((name, index) => {
        const action = (form.getAll('ruleAction') as string[])[index].trim();
        const agentScope = (form.getAll('ruleScope') as string[])[index] as RuleInput['agentScope'];
        const targetAgentId = (form.getAll('targetAgentId') as string[])[index].trim();
        const effect = (form.getAll('ruleEffect') as string[])[index] as RuleInput['effect'];
        const conditionText = (form.getAll('ruleConditions') as string[])[index].trim();
        return { name: name.trim(), action, agentScope, targetAgentId: agentScope === 'SPECIFIC_AGENT' ? targetAgentId : null, effect, conditions: conditionText ? JSON.parse(conditionText) : null };
      });
      const definition: PolicyDefinition = { name: String(form.get('name')).trim(), description: String(form.get('description')).trim(), priority: Number(form.get('priority')), rules };
      if (editing) await api.updatePolicy(editing.policyId, definition); else await api.createPolicy(definition);
      setNotice(editing ? 'A new draft version was created.' : 'Policy draft created.'); setModal(false); await load();
    } catch (reason) { setNotice(reason instanceof Error ? reason.message : 'Policy could not be saved. Check the rule conditions JSON.'); }
  }

  return <div className="page-stack"><PageHeading eyebrow="AUTHORIZATION CONTROL" title="Security Policies" description="Versioned, deterministic access rules for every registered agent." actions={canManage && <AddButton onClick={openCreate}>Create policy</AddButton>} />
    {notice && <div className="inline-notice" role="status"><span>{notice}</span><button aria-label="Dismiss notification" onClick={() => setNotice('')}><X size={15} /></button></div>}
    <div className="policy-summary"><div><span className="policy-summary-icon"><ShieldCheck size={18} /></span><div><strong>{policies.length}</strong><small>policy definitions</small></div></div><div className="summary-divider" /><div><span className="summary-dot summary-active" /><div><strong>{policies.filter((policy) => policy.status === 'ACTIVE').length}</strong><small>active policies</small></div></div><span className="policy-authority"><Shield size={15} />Final authorization authority</span></div>
    <section className="panel policy-panel"><div className="inventory-toolbar"><div><div className="eyebrow">ORGANIZATION POLICY SET</div><h2 className="section-title">Policy definitions</h2></div><div className="toolbar-filters"><span className="filter-icon"><ShieldAlert size={15} /></span><select value={filter} onChange={(event) => setFilter(event.target.value)} aria-label="Filter policies by status"><option value="ALL">All statuses</option><option value="ACTIVE">Active</option><option value="DRAFT">Draft</option><option value="DISABLED">Disabled</option></select><button className="icon-button" aria-label="Refresh policies" onClick={() => void load()}><RefreshCw size={16} /></button></div></div>
      {loading ? <LoadingState label="Loading policies" /> : error ? <ErrorState message={error} onRetry={() => void load()} /> : visible.length === 0 ? <EmptyState title={policies.length ? 'No policies match this filter' : 'No policies defined'} body={policies.length ? 'Select another status to see policy definitions.' : 'Create a draft with explicit rules, then activate it through the Policy Engine.'} action={canManage && !policies.length && <AddButton onClick={openCreate}>Create first policy</AddButton>} /> : <div className="policy-grid">{visible.map((policy) => <article className="policy-card" key={policy.policyId}>
        <div className="policy-card-top"><span className={`policy-icon policy-${policy.status.toLowerCase()}`}><Shield size={19} /></span><StatusBadge status={policy.status} /><button className="icon-button" aria-label={`Open ${policy.name}`} onClick={() => void showPolicy(policy)}><FileClock size={16} /></button></div>
        <button className="policy-title-button" onClick={() => void showPolicy(policy)}><h3>{policy.name}</h3></button><p>{policy.description || 'No description provided.'}</p>
        <div className="policy-rule-strip"><span><GitBranch size={14} />Version {policy.version}</span><span>{policy.rules.length} {policy.rules.length === 1 ? 'rule' : 'rules'}</span><span>Priority {policy.priority}</span></div>
        <div className="policy-rule-preview">{policy.rules.slice(0, 3).map((rule) => <div key={rule.id ?? `${rule.name}:${rule.action}`}><span className={`effect-pill effect-${rule.effect.toLowerCase()}`}>{rule.effect}</span><span>{rule.action}</span><small>{rule.agentScope === 'ALL_AGENTS' ? 'All agents' : 'Specific agent'}</small></div>)}{policy.rules.length > 3 && <span className="more-rules">+{policy.rules.length - 3} additional rules</span>}</div>
        <div className="policy-card-footer"><span>Updated {new Date(policy.updatedAt).toLocaleDateString()}</span><Button variant="ghost" onClick={() => void showPolicy(policy)}>View details <span aria-hidden>→</span></Button></div>
      </article>)}</div>}
    </section>
    {modal && <PolicyFormModal editing={editing} onClose={() => setModal(false)} onSubmit={save} />}
    {selected && <Modal wide title={selected.name} subtitle={`Policy ${selected.policyId} · current version ${selected.version}`} onClose={() => setSelected(null)}><div className="policy-detail-content"><div className="policy-detail-meta"><StatusBadge status={selected.status} /><span>Priority {selected.priority}</span><span>{selected.rules.length} rules</span></div><p>{selected.description || 'No description provided.'}</p><h3>Current version rules</h3><div className="detail-rule-list">{selected.rules.map((rule) => <div className="detail-rule" key={rule.id}><span className={`effect-pill effect-${rule.effect.toLowerCase()}`}>{rule.effect}</span><div><strong>{rule.name}</strong><span>{rule.action} · {rule.agentScope === 'ALL_AGENTS' ? 'All agents' : rule.targetAgentId}</span></div><small>{rule.conditions ? 'Conditional' : 'No conditions'}</small></div>)}</div><h3 className="version-heading">Version history</h3>{versionLoading ? <LoadingState label="Loading version history" /> : versions.length ? <div className="version-list">{versions.map((version) => <div key={version.versionId}><span><GitBranch size={14} />Version {version.version}{version.latest && <i>Latest</i>}</span><StatusBadge status={version.status} /><small>{new Date(version.createdAt).toLocaleString()}</small></div>)}</div> : <div className="small-empty">Version history is unavailable.</div>}
      {canManage && <div className="form-footer modal-action-row"><Button variant="secondary" onClick={() => openEdit(selected)}>Create new version</Button>{selected.status !== 'ACTIVE' ? <Button onClick={() => void statusChange(selected, 'ACTIVE')}>Activate version</Button> : <Button variant="danger" onClick={() => void statusChange(selected, 'DISABLED')}>Disable policy</Button>}</div>}</div></Modal>}
  </div>;
}

function PolicyFormModal({ editing, onClose, onSubmit }: { editing: Policy | null; onClose: () => void; onSubmit: (event: FormEvent<HTMLFormElement>) => void }) {
  const initial: RuleInput[] = editing?.rules.map((rule) => ({ name: rule.name, agentScope: rule.agentScope, targetAgentId: rule.targetAgentId ?? '', action: rule.action, effect: rule.effect, conditionJson: rule.conditions ? JSON.stringify(rule.conditions, null, 2) : '' })) ?? [{ ...blankRule }];
  const [rules, setRules] = useState(initial);
  return <Modal wide title={editing ? 'Create a new policy version' : 'Create policy'} subtitle={editing ? 'Policy changes are saved as a new draft version. Previous versions remain available.' : 'Start with explicit deterministic rules. DENY takes precedence during evaluation.'} onClose={onClose}>
    <form className="policy-form" onSubmit={onSubmit}><div className="policy-form-general"><FormField label="Policy name"><input name="name" maxLength={150} required defaultValue={editing?.name ?? ''} placeholder="e.g. Customer data access" /></FormField><FormField label="Priority"><input name="priority" type="number" min="0" required defaultValue={editing?.priority ?? 10} /></FormField><FormField label="Description"><textarea name="description" rows={2} maxLength={1000} defaultValue={editing?.description ?? ''} placeholder="Purpose and scope of this policy" /></FormField></div>
      <div className="policy-form-rules-heading"><div><div className="eyebrow">RULE SET</div><h3>Rules <span>{rules.length}</span></h3></div><Button type="button" variant="secondary" onClick={() => setRules([...rules, { ...blankRule }])}><Plus size={15} />Add rule</Button></div>
      {rules.map((rule, index) => <div className="rule-editor" key={index}><div className="rule-editor-title"><span>RULE {String(index + 1).padStart(2, '0')}</span>{rules.length > 1 && <button type="button" className="icon-button" aria-label={`Remove rule ${index + 1}`} onClick={() => setRules(rules.filter((_, i) => i !== index))}><X size={15} /></button>}</div><div className="form-grid"><FormField label="Rule name"><input name="ruleName" required maxLength={150} defaultValue={rule.name} /></FormField><FormField label="Action / tool"><input name="ruleAction" required maxLength={150} defaultValue={rule.action} placeholder="document.read" /></FormField><FormField label="Effect"><select name="ruleEffect" defaultValue={rule.effect}><option value="ALLOW">ALLOW</option><option value="DENY">DENY</option></select></FormField><FormField label="Agent scope"><select name="ruleScope" defaultValue={rule.agentScope} onChange={(event) => { const next = [...rules]; next[index] = { ...next[index], agentScope: event.target.value as RuleInput['agentScope'] }; setRules(next); }}><option value="ALL_AGENTS">All agents</option><option value="SPECIFIC_AGENT">Specific agent</option></select></FormField>{rule.agentScope === 'SPECIFIC_AGENT' && <div className="form-span"><FormField label="Target agent UUID"><input name="targetAgentId" required defaultValue={rule.targetAgentId} placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" /></FormField></div>}{rule.agentScope !== 'SPECIFIC_AGENT' && <input name="targetAgentId" type="hidden" value="" readOnly />}
        <div className="form-span"><FormField label="Conditions (JSON, optional)" hint="Use the Policy Engine condition schema: { join: ALL|ANY, clauses: [{ field, operator, value }] }."><textarea name="ruleConditions" rows={3} defaultValue={rule.conditionJson} placeholder={'{"join":"ALL","clauses":[{"field":"resource.classification","operator":"EQUALS","value":"public"}]}'}/></FormField></div></div></div>)}
      <div className="form-footer"><Button type="button" variant="secondary" onClick={onClose}>Cancel</Button><Button type="submit">{editing ? 'Save new draft version' : 'Create draft policy'}</Button></div></form>
  </Modal>;
}
