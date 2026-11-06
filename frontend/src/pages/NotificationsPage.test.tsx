import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { NotificationsPage } from './NotificationsPage';

const { notifications, notification, mark, markAll, role } = vi.hoisted(()=>({notifications:vi.fn(),notification:vi.fn(),mark:vi.fn(),markAll:vi.fn(),role:{value:'ADMIN'}}));
vi.mock('../lib/api',()=>({api:{notifications,notification,markNotificationRead:mark,markAllNotificationsRead:markAll}}));
vi.mock('../context/auth-context',()=>({useAuth:()=>({session:{claims:{organization_role:role.value}}})}));
const row={notificationId:'notice-1',category:'AI_THREAT',severity:'HIGH',title:'Threat detected',description:'Security analysis found a risk.',sourceEventType:'AI_THREAT_DETECTED',agentId:'agent-1',executionId:null,sourceIdentifier:'PROMPT_INJECTION',correlationId:'corr-1',eventTimestamp:'2026-11-04T10:00:00Z',createdAt:'2026-11-04T10:00:00Z',readAt:null};
describe('NotificationsPage',()=>{
  beforeEach(()=>{role.value='ADMIN';notifications.mockReset();notification.mockReset();mark.mockReset();markAll.mockReset();notifications.mockResolvedValue({content:[row],page:0,size:20,totalElements:1,totalPages:1});notification.mockResolvedValue(row);mark.mockResolvedValue({...row,readAt:'2026-11-04T11:00:00Z'});markAll.mockResolvedValue({updated:1});});
  it('shows live notifications and supports detail and read actions',async()=>{const user=userEvent.setup();render(<NotificationsPage/>);expect(await screen.findByText('Threat detected')).toBeInTheDocument();await user.click(screen.getByRole('button',{name:'View Threat detected'}));expect(await screen.findByText('Security analysis found a risk.')).toBeInTheDocument();expect(notification).toHaveBeenCalledWith('notice-1');await user.click(screen.getByRole('button',{name:/mark as read/i}));expect(mark).toHaveBeenCalledWith('notice-1');await user.click(screen.getByRole('button',{name:'Mark all read'}));expect(markAll).toHaveBeenCalled();});
  it('does not request the admin notification API for a MEMBER',()=>{role.value='MEMBER';render(<NotificationsPage/>);expect(screen.getByText('Administrator access required')).toBeInTheDocument();expect(notifications).not.toHaveBeenCalled();});
  it('shows empty and unavailable states',async()=>{notifications.mockResolvedValueOnce({content:[],page:0,size:20,totalElements:0,totalPages:0});const {unmount}=render(<NotificationsPage/>);expect(await screen.findByText('No notifications found')).toBeInTheDocument();unmount();notifications.mockRejectedValueOnce(new Error('Offline'));render(<NotificationsPage/>);expect(await screen.findByText('Offline')).toBeInTheDocument();});
});
