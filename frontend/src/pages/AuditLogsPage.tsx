import { useEffect, useState } from 'react';
import { Eye, Filter, ShieldCheck } from 'lucide-react';
import { Button, EmptyState, ErrorState, LoadingState, Modal, PageHeading, StatusBadge } from '../components/UI';
import { api } from '../lib/api';
import type { AuditEvent, SpringPage } from '../types';

const eventTypes=['AGENT_REGISTERED','AGENT_UPDATED','AGENT_DEACTIVATED','POLICY_CREATED','POLICY_UPDATED','POLICY_ACTIVATED','RUNTIME_AUTHORIZATION_ALLOW','RUNTIME_AUTHORIZATION_DENY','TOOL_EXECUTION_SUCCEEDED','TOOL_EXECUTION_FAILED','AI_THREAT_DETECTED','AGENT_TRUST_SCORE_UPDATED'];
function asInstant(value:string){return value?new Date(value).toISOString():undefined;}
export function AuditLogsPage(){
  const [data,setData]=useState<SpringPage<AuditEvent>|null>(null);const [loading,setLoading]=useState(true);const [error,setError]=useState('');const [page,setPage]=useState(0);const [refresh,setRefresh]=useState(0);
  const [eventType,setEventType]=useState('');const [agentId,setAgentId]=useState('');const [outcome,setOutcome]=useState('');const [from,setFrom]=useState('');const [to,setTo]=useState('');
  const [selected,setSelected]=useState<AuditEvent|null>(null);const [detail,setDetail]=useState<AuditEvent|null>(null);const [detailError,setDetailError]=useState('');
  useEffect(()=>{let active=true;setLoading(true);setError('');api.auditEvents({page,size:20,eventType:eventType||undefined,agentId:agentId||undefined,outcome:outcome||undefined,from:asInstant(from),to:asInstant(to)})
    .then(value=>{if(active)setData(value);}).catch(reason=>{if(active)setError(reason instanceof Error?reason.message:'Audit events could not be loaded.');}).finally(()=>{if(active)setLoading(false);});return()=>{active=false;};},[page,eventType,agentId,outcome,from,to,refresh]);
  useEffect(()=>{if(!selected){setDetail(null);return;}let active=true;setDetail(null);setDetailError('');api.auditEvent(selected.eventId).then(value=>{if(active)setDetail(value);}).catch(reason=>{if(active)setDetailError(reason instanceof Error?reason.message:'Event details could not be loaded.');});return()=>{active=false;};},[selected]);
  const pageCount=data?.totalPages??0;
  return <div className="page-stack"><PageHeading eyebrow="EVIDENCE & COMPLIANCE" title="Audit logs" description="Search immutable organization-scoped security records. Policy decisions and tool execution outcomes are recorded separately." />
    <section className="panel"><div className="telemetry-filters" aria-label="Audit filters">
      <label>Event type<select aria-label="Event type" value={eventType} onChange={e=>{setPage(0);setEventType(e.target.value);}}><option value="">All event types</option>{eventTypes.map(type=><option key={type}>{type}</option>)}</select></label>
      <label>Agent ID<input aria-label="Agent ID" value={agentId} onChange={e=>{setPage(0);setAgentId(e.target.value);}} placeholder="Filter by agent UUID" /></label>
      <label>Decision / outcome<select aria-label="Decision or outcome" value={outcome} onChange={e=>{setPage(0);setOutcome(e.target.value);}}><option value="">All outcomes</option>{['ALLOW','DENY','SUCCEEDED','FAILED'].map(v=><option key={v}>{v}</option>)}</select></label>
      <label>From<input aria-label="From date" type="datetime-local" value={from} onChange={e=>{setPage(0);setFrom(e.target.value);}} /></label>
      <label>To<input aria-label="To date" type="datetime-local" value={to} onChange={e=>{setPage(0);setTo(e.target.value);}} /></label><span className="filter-note"><Filter size={14}/> Tenant context comes from your verified session</span>
    </div></section>
    <section className="panel table-panel"><div className="panel-heading"><div><div className="eyebrow">IMMUTABLE SECURITY RECORDS</div><h2>Event history</h2></div><span className="tag tag-muted">{data?.totalElements??'—'} records</span></div>
      {loading?<LoadingState label="Loading organization audit events"/>:error?<ErrorState message={error} onRetry={()=>setRefresh(v=>v+1)}/>:data?.content.length?<><div className="table-scroll"><table className="data-table"><thead><tr><th>Time / event</th><th>Agent / action</th><th>Policy decision</th><th>Execution outcome</th><th>Resource</th><th>Details</th></tr></thead><tbody>{data.content.map(e=><tr key={e.eventId}><td><strong>{e.eventType.replaceAll('_',' ')}</strong><small className="telemetry-reason"><time dateTime={e.eventTimestamp}>{new Date(e.eventTimestamp).toLocaleString()}</time></small></td><td><span>{e.agentId??e.actorIdentity}</span><small className="telemetry-reason">{e.action??'—'}</small></td><td>{e.decision?<StatusBadge status={e.decision}/>:<span>—</span>}</td><td>{e.executionOutcome?<StatusBadge status={e.executionOutcome}/>:<span>—</span>}</td><td>{e.resource??'—'}</td><td><Button variant="ghost" aria-label={`View ${e.eventType} details`} onClick={()=>setSelected(e)}><Eye size={15}/> View</Button></td></tr>)}</tbody></table></div>
        <div className="table-pagination"><span>Page {data.page+1} of {Math.max(1,pageCount)} · {data.totalElements} events</span><Button variant="secondary" disabled={page<=0} onClick={()=>setPage(v=>Math.max(0,v-1))}>Previous</Button><Button variant="secondary" disabled={page+1>=pageCount} onClick={()=>setPage(v=>v+1)}>Next</Button></div></>:<EmptyState title="No audit events found" body="There are no records matching the selected filters."/>}
    </section><div className="integration-note"><ShieldCheck size={16}/><span>Audit access is tenant-scoped. Members see runtime decisions, execution results and AI threats only. AI findings are advisory; Policy Engine decisions remain authoritative.</span></div>
    {selected&&<Modal title="Audit event" subtitle={selected.eventId} onClose={()=>setSelected(null)} wide>{detailError?<ErrorState message={detailError}/>:!detail?<LoadingState label="Loading event details"/>:<div className="organization-profile-details">
      <div className="organization-detail-row"><span>Event</span><strong>{detail.eventType}</strong></div><div className="organization-detail-row"><span>Actor</span><code>{detail.actorType} · {detail.actorIdentity}</code></div>
      <div className="organization-detail-row"><span>Agent / execution</span><code>{detail.agentId??'—'} / {detail.executionId??'—'}</code></div><div className="organization-detail-row"><span>Action / resource</span><code>{detail.action??'—'} / {detail.resource??'—'}</code></div>
      <div className="organization-detail-row"><span>Policy decision</span>{detail.decision?<StatusBadge status={detail.decision}/>:<span>—</span>}</div><div className="organization-detail-row"><span>Execution outcome</span>{detail.executionOutcome?<StatusBadge status={detail.executionOutcome}/>:<span>—</span>}</div>
      <div className="organization-detail-row"><span>Reason</span><span>{detail.reason??'—'}</span></div><div className="organization-detail-row"><span>Correlation ID</span><code>{detail.correlationId}</code></div><div className="organization-detail-row"><span>Event / received time</span><time>{new Date(detail.eventTimestamp).toLocaleString()} / {new Date(detail.receivedTimestamp).toLocaleString()}</time></div>
    </div>}</Modal>}
  </div>;
}
