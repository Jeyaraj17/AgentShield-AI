import { useEffect, useState, type ReactNode } from 'react';
import { NavLink, useLocation, useNavigate } from 'react-router-dom';
import { Activity, Bot, Bell, ChevronDown, ChevronLeft, ChevronRight, Command, Gauge, LayoutDashboard, LogOut, Menu, Search, Settings2, ShieldCheck, Sparkles, ScrollText, X } from 'lucide-react';
import { useAuth } from '../context/auth-context';
import { api } from '../lib/api';
import type { UserProfile } from '../types';

const items = [
  { label: 'Overview', path: '/', icon: LayoutDashboard },
  { label: 'AI Agents', path: '/agents', icon: Bot },
  { label: 'Security Policies', path: '/policies', icon: ShieldCheck },
  { label: 'Runtime Monitoring', path: '/runtime', icon: Activity },
  { label: 'AI Analysis', path: '/analysis', icon: Sparkles },
  { label: 'Trust & Risk', path: '/trust', icon: Gauge },
  { label: 'Audit Logs', path: '/audit', icon: ScrollText },
  { label: 'Notifications', path: '/notifications', icon: Bell },
  { label: 'Organization Settings', path: '/organization', icon: Settings2 },
];

export function AppShell({ children }: { children: ReactNode }) {
  const { session, signOut } = useAuth();
  const [collapsed, setCollapsed] = useState(() =>
    typeof window.matchMedia === 'function' && window.matchMedia('(max-width: 1020px) and (min-width: 781px)').matches,
  );
  const [mobileOpen, setMobileOpen] = useState(false);
  const [profileOpen, setProfileOpen] = useState(false);
  const [orgOpen, setOrgOpen] = useState(false);
  const [profile, setProfile] = useState<UserProfile | null>(null);
  const location = useLocation();
  const navigate = useNavigate();

  useEffect(() => {
    if (!session) return;
    api.me().then(setProfile).catch(() => setProfile(null));
  }, [session]);
  useEffect(() => { setMobileOpen(false); setProfileOpen(false); setOrgOpen(false); }, [location.pathname]);

  const current = items.find((item) => item.path === location.pathname);
  const name = profile ? `${profile.firstName} ${profile.lastName}` : 'Workspace user';
  const initials = profile ? `${profile.firstName.charAt(0)}${profile.lastName.charAt(0)}`.toUpperCase() : 'AS';
  const orgId = session?.claims.organization_id ?? '';

  return <div className={`app-shell ${collapsed ? 'sidebar-collapsed' : ''}`}>
    {mobileOpen && <button className="mobile-scrim" aria-label="Close navigation" onClick={() => setMobileOpen(false)} />}
    <aside className={`sidebar ${mobileOpen ? 'mobile-open' : ''}`}>
      <div className="sidebar-brand"><span className="brand-emblem">A</span><span className="brand-name">AgentShield <b>AI</b><small>SECURITY PLATFORM</small></span>
        <button className="sidebar-collapse icon-button" aria-label={collapsed ? 'Expand sidebar' : 'Collapse sidebar'} title={collapsed ? 'Expand sidebar' : 'Collapse sidebar'} aria-expanded={!collapsed} onClick={() => setCollapsed(!collapsed)}>{collapsed ? <ChevronRight size={16} /> : <ChevronLeft size={16} />}</button>
        <button className="mobile-sidebar-close icon-button" aria-label="Close navigation" onClick={() => setMobileOpen(false)}><X size={19} /></button>
      </div>
      <div className="workspace-label">WORKSPACE</div>
      <nav className="side-navigation" aria-label="Main navigation">
        {items.map(({ label, path, icon: Icon }) => <NavLink key={path} to={path} end={path === '/'} title={collapsed ? label : undefined} className={({ isActive }) => `nav-link ${isActive ? 'active' : ''}`}>
          <Icon size={18} strokeWidth={1.8} /><span>{label}</span>
        </NavLink>)}
      </nav>
      <div className="sidebar-bottom"><div className="security-posture"><div className="posture-icon"><ShieldCheck size={16} /></div><div><strong>Policy control</strong><span>Policy Engine authority</span></div></div></div>
    </aside>

    <div className="main-column">
      <header className="topbar">
        <button className="icon-button mobile-menu" aria-label="Open navigation" onClick={() => setMobileOpen(true)}><Menu size={20} /></button>
        <div className="breadcrumbs"><span>Workspace</span><ChevronRight size={14} /><strong>{current?.label ?? 'Overview'}</strong></div>
        <div className="topbar-tools">
          <div className="search-shell"><Search size={16} /><input aria-label="Global search unavailable" placeholder="Global search unavailable" disabled /><kbd><Command size={11} /> K</kbd></div>
          <div className="popover-wrap">
            <button className={`org-switcher ${orgOpen ? 'open' : ''}`} onClick={() => { setOrgOpen(!orgOpen); setProfileOpen(false); }} aria-expanded={orgOpen}>
              <span className="org-avatar"><ShieldCheck size={15} /></span><span className="org-copy"><small>ACTIVE ORGANIZATION</small><b>{orgId ? `Workspace · ${orgId.slice(0, 8)}` : 'Current organization'}</b></span><ChevronDown size={15} />
            </button>
            {orgOpen && <div className="popover org-popover"><span className="popover-kicker">ORGANIZATION CONTEXT</span><strong>{orgId || 'Not available'}</strong><p>Tenant context is taken from your verified access token. Organization switching is not exposed by the API Gateway yet.</p></div>}
          </div>
          <button className="notification-button" aria-label="Open notifications" title="Open notifications" onClick={() => navigate('/notifications')}><Bell size={18} /></button>
          <div className="popover-wrap profile-wrap">
            <button className="profile-button" onClick={() => { setProfileOpen(!profileOpen); setOrgOpen(false); }} aria-expanded={profileOpen}>
              <span className="profile-avatar">{initials}</span><span className="profile-copy"><b>{name}</b><small>{session?.claims.organization_role}</small></span><ChevronDown size={14} />
            </button>
            {profileOpen && <div className="popover profile-popover"><div className="profile-popover-user"><span className="profile-avatar">{initials}</span><div><strong>{name}</strong><small>{profile?.email ?? session?.claims.sub}</small></div></div><button className="signout-action" onClick={() => signOut()}><LogOut size={15} />Sign out of this browser session</button><p>Identity Service SSO session may remain active until its own logout endpoint is routed.</p></div>}
          </div>
        </div>
      </header>
      <main className="content-area">{children}</main>
      <footer className="app-footer"><span><span className="footer-mark" />AgentShield AI Security Console</span><span>Tenant isolated · {orgId ? orgId.slice(0, 8) : 'identity unavailable'}</span></footer>
    </div>
  </div>;
}
