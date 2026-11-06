import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { AuditLogsPage } from './AuditLogsPage';

const { events, event } = vi.hoisted(() => ({ events: vi.fn(), event: vi.fn() }));
vi.mock('../lib/api',()=>({api:{auditEvents:events,auditEvent:event}}));
const sample={eventId:'event-1',eventType:'RUNTIME_AUTHORIZATION_DENY',actorIdentity:'agent-1',actorType:'AGENT',agentId:'agent-1',executionId:'exec-1',action:'invoice.read',resource:'invoice-9',decision:'DENY',reason:'POLICY_DENY',executionOutcome:null,correlationId:'corr-1',eventTimestamp:'2026-11-04T10:00:00Z',receivedTimestamp:'2026-11-04T10:00:01Z'};
describe('AuditLogsPage',()=>{
  beforeEach(()=>{events.mockReset();event.mockReset();events.mockResolvedValue({content:[sample],page:0,size:20,totalElements:1,totalPages:1});event.mockResolvedValue(sample);});
  it('shows real events with decision separated from outcome and loads details',async()=>{
    const user=userEvent.setup();render(<AuditLogsPage/>);
    expect(await screen.findByText('RUNTIME AUTHORIZATION DENY')).toBeInTheDocument();
    expect(screen.getByText('DENY',{selector:'.status-badge'})).toBeInTheDocument();expect(screen.getAllByText('—').length).toBeGreaterThan(0);
    await user.click(screen.getByRole('button',{name:/view runtime_authorization_deny details/i}));
    expect(await screen.findByText('POLICY_DENY')).toBeInTheDocument();expect(event).toHaveBeenCalledWith('event-1');
  });
  it('passes filters and renders an empty state',async()=>{
    const user=userEvent.setup();events.mockResolvedValue({content:[],page:0,size:20,totalElements:0,totalPages:0});render(<AuditLogsPage/>);
    expect(await screen.findByText('No audit events found')).toBeInTheDocument();
    await user.selectOptions(screen.getByLabelText('Decision or outcome'),'DENY');
    expect(events).toHaveBeenLastCalledWith(expect.objectContaining({outcome:'DENY'}));
  });
  it('displays retryable service errors',async()=>{events.mockRejectedValueOnce(new Error('Audit unavailable'));render(<AuditLogsPage/>);expect(await screen.findByText('Audit unavailable')).toBeInTheDocument();});
});
