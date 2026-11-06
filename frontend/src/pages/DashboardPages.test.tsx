import { render, screen } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { OrganizationSettingsPage } from './DashboardPages';

const { me, organization, membership, members, authSession } = vi.hoisted(() => ({
  me: vi.fn(), organization: vi.fn(), membership: vi.fn(), members: vi.fn(),
  authSession: { claims: { user_id: 'user-1', organization_id: 'org-verified', organization_role: 'OWNER' } },
}));
vi.mock('../lib/api', () => ({ api: { me, currentOrganization: organization, currentMembership: membership, organizationMembers: members } }));
vi.mock('../context/auth-context', () => ({
  useAuth: () => ({ session: authSession }),
}));

describe('remaining dashboard pages', () => {
  beforeEach(() => {
    authSession.claims.organization_role = 'OWNER';
    me.mockReset(); organization.mockReset(); membership.mockReset(); members.mockReset();
    organization.mockResolvedValue({ id: 'org-verified', name: 'Example Workspace', organizationCode: 'EXAMPLE', status: 'ACTIVE' });
    membership.mockResolvedValue({ id: 'membership-1', userId: 'user-1', organizationId: 'org-verified', role: 'OWNER', status: 'ACTIVE', joinedAt: '2026-01-01T00:00:00Z' });
    members.mockResolvedValue([]);
  });

  it('shows verified tenant context and the live self-profile response', async () => {
    me.mockResolvedValue({ id: 'user-1', email: 'owner@example.com', firstName: 'Ari', lastName: 'Owner', status: 'ACTIVE' });
    render(<OrganizationSettingsPage />);
    expect(screen.getByText('org-verified')).toBeInTheDocument();
    expect(await screen.findByText('Ari Owner')).toBeInTheDocument();
    expect(screen.getByText('owner@example.com')).toBeInTheDocument();
    expect(await screen.findAllByText('Example Workspace')).toHaveLength(2);
    expect(screen.getByRole('heading', { name: 'Organization members' })).toBeInTheDocument();
    expect(screen.getByText('No organization members')).toBeInTheDocument();
  });

  it('renders a retryable API error for the profile instead of placeholder identity data', async () => {
    me.mockRejectedValue(new Error('Profile unavailable'));
    render(<OrganizationSettingsPage />);
    expect(await screen.findByText('Profile unavailable')).toBeInTheDocument();
    expect(screen.queryByText('Workspace user')).not.toBeInTheDocument();
  });

  it('does not request or render the organization directory for a MEMBER', async () => {
    authSession.claims.organization_role = 'MEMBER';
    me.mockResolvedValue({ id: 'user-1', email: 'member@example.com', firstName: 'Ari', lastName: 'Member', status: 'ACTIVE' });
    membership.mockResolvedValue({ id: 'membership-1', userId: 'user-1', organizationId: 'org-verified', role: 'MEMBER', status: 'ACTIVE', joinedAt: '2026-01-01T00:00:00Z' });
    render(<OrganizationSettingsPage />);
    expect(await screen.findByText('member@example.com')).toBeInTheDocument();
    expect(members).not.toHaveBeenCalled();
    expect(screen.queryByRole('heading', { name: 'Organization members' })).not.toBeInTheDocument();
    expect(screen.getByText(/member directory is limited/i)).toBeInTheDocument();
  });
});
