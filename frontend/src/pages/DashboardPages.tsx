import { useCallback, useEffect, useState } from 'react';
import { AlertTriangle, Building2, CheckCircle2, Fingerprint, LockKeyhole } from 'lucide-react';
import { PageHeading, EmptyState, ErrorState, LoadingState, StatusBadge } from '../components/UI';
import { api } from '../lib/api';
import { useAuth } from '../context/auth-context';
import type { CurrentMembership, CurrentOrganization, OrganizationMember, UserProfile } from '../types';

export function OrganizationSettingsPage() {
  const { session } = useAuth();
  const [profile, setProfile] = useState<UserProfile | null>(null);
  const [organization, setOrganization] = useState<CurrentOrganization | null>(null);
  const [membership, setMembership] = useState<CurrentMembership | null>(null);
  const [members, setMembers] = useState<OrganizationMember[] | null>(null);
  const [loading, setLoading] = useState(true);
  const [errors, setErrors] = useState<Record<string, string>>({});
  const [refresh, setRefresh] = useState(0);
  const canViewDirectory = session?.claims.organization_role === 'OWNER' || session?.claims.organization_role === 'ADMIN';
  const load = useCallback(async () => {
    if (!session) return;
    setLoading(true); setErrors({});
    setOrganization(null); setProfile(null); setMembership(null); setMembers(null);
    const tasks: Array<[string, () => Promise<unknown>]> = [
      ['organization', api.currentOrganization], ['profile', api.me], ['membership', api.currentMembership],
    ];
    if (canViewDirectory) tasks.push(['members', api.organizationMembers]);
    const results = await Promise.allSettled(tasks.map(([, loadValue]) => loadValue()));
    const nextErrors: Record<string, string> = {};
    results.forEach((result, index) => {
      const key = tasks[index][0];
      if (result.status === 'rejected') nextErrors[key] = result.reason instanceof Error ? result.reason.message : 'This organization data could not be loaded.';
      else if (key === 'organization') setOrganization(result.value as CurrentOrganization);
      else if (key === 'profile') setProfile(result.value as UserProfile);
      else if (key === 'membership') setMembership(result.value as CurrentMembership);
      else if (key === 'members') setMembers(result.value as OrganizationMember[]);
    });
    setErrors(nextErrors); setLoading(false);
  }, [session, canViewDirectory]);
  useEffect(() => { void load(); }, [load, refresh]);

  const orgId = session?.claims.organization_id ?? '';
  const role = membership?.role ?? session?.claims.organization_role ?? 'Unknown';
  return <div className="page-stack">
    <PageHeading eyebrow="TENANT ADMINISTRATION" title="Organization settings" description="Review the verified organization context and identity attached to this session." />
    <div className="organization-context-banner"><div className="organization-context-icon"><Building2 size={20} /></div><div><span>ACTIVE ORGANIZATION · VERIFIED TOKEN CLAIM</span><strong>{orgId || 'Organization context unavailable'}</strong><small>{organization?.name ?? 'Organization name not loaded'}</small></div><StatusBadge status={role} /></div>
    <div className="organization-settings-grid">
      <section className="panel organization-profile-panel">
        <div className="panel-heading"><div><div className="eyebrow">SIGNED-IN IDENTITY</div><h2>My profile</h2></div><Fingerprint size={18} /></div>
        {loading ? <LoadingState label="Loading your profile and membership" /> : errors.profile || errors.membership ? <ErrorState message={errors.profile || errors.membership} onRetry={() => setRefresh((value) => value + 1)} /> : profile && membership ? <div className="organization-profile-details">
          <div className="organization-person"><span className="organization-person-avatar">{`${profile.firstName[0] ?? ''}${profile.lastName[0] ?? ''}`.toUpperCase()}</span><div><strong>{profile.firstName} {profile.lastName}</strong><span>{profile.email}</span></div></div>
          <div className="organization-detail-row"><span>Account status</span><StatusBadge status={profile.status} /></div>
          <div className="organization-detail-row"><span>User ID</span><code>{profile.id}</code></div>
          <div className="organization-detail-row"><span>Membership role</span><StatusBadge status={membership.role} /></div>
          <div className="organization-detail-row"><span>Membership status</span><StatusBadge status={membership.status} /></div>
          <div className="organization-detail-row"><span>Joined organization</span><time dateTime={membership.joinedAt}>{new Date(membership.joinedAt).toLocaleDateString()}</time></div>
        </div> : <div className="organization-empty"><AlertTriangle size={17} /> Profile or membership data was not returned.</div>}
      </section>
      <section className="panel organization-admin-panel">
        <div className="panel-heading"><div><div className="eyebrow">ORGANIZATION PROFILE</div><h2>Workspace details</h2></div><Building2 size={18} /></div>
        {loading ? <LoadingState label="Loading organization details" /> : errors.organization ? <ErrorState message={errors.organization} onRetry={() => setRefresh((value) => value + 1)} /> : organization ? <div className="organization-profile-details">
          <div className="organization-person"><span className="organization-person-avatar"><Building2 size={16} /></span><div><strong>{organization.name}</strong><span>Organization code · {organization.organizationCode}</span></div></div>
          <div className="organization-detail-row"><span>Organization status</span><StatusBadge status={organization.status} /></div>
          <div className="organization-detail-row"><span>Organization ID</span><code>{organization.id}</code></div>
          <div className="organization-detail-row"><span>Your role</span><StatusBadge status={role} /></div>
        </div> : <EmptyState title="Organization details unavailable" body="Identity Service did not return this tenant’s organization record." />}
      </section>
    </div>
    {canViewDirectory ? <section className="panel organization-directory-panel">
      <div className="panel-heading"><div><div className="eyebrow">ACCESS DIRECTORY</div><h2>Organization members</h2><p>Member information is scoped by Identity Service to the organization in your authenticated session.</p></div><span className="tag tag-muted">{members?.length ?? '—'} members</span></div>
      {loading ? <LoadingState label="Loading organization members" /> : errors.members ? <ErrorState message={errors.members} onRetry={() => setRefresh((value) => value + 1)} /> : members?.length ? <div className="table-scroll"><table className="data-table"><thead><tr><th>Member</th><th>Account</th><th>Organization role</th><th>Membership</th><th>Joined</th></tr></thead><tbody>{members.map((member) => <tr key={member.userId}><td><div className="organization-member-cell"><strong>{member.firstName} {member.lastName}</strong><small>{member.email}</small></div></td><td><StatusBadge status={member.accountStatus} /></td><td><StatusBadge status={member.role} /></td><td><StatusBadge status={member.membershipStatus} /></td><td><time dateTime={member.joinedAt}>{new Date(member.joinedAt).toLocaleDateString()}</time></td></tr>)}</tbody></table></div> : <EmptyState title="No organization members" body="There are no membership records to display for this organization." />}
    </section> : <div className="integration-note"><LockKeyhole size={16} /><span>Member directory is limited to OWNER and ADMIN. Your own membership details remain visible above.</span></div>}
    {canViewDirectory && <div className="integration-note"><CheckCircle2 size={16} /><span>Organization and member data are scoped from verified claims. Role and organization request headers are ignored.</span><span className="organization-management-note">Member and role management is not available here.</span></div>}
  </div>;
}
