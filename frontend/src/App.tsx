import { useEffect, useState } from 'react';
import { Navigate, Outlet, Route, Routes, useNavigate, useSearchParams } from 'react-router-dom';
import { AuthProvider } from './context/AuthContext';
import { useAuth } from './context/auth-context';
import { finishLogin } from './lib/auth';
import { AppShell } from './components/Shell';
import { LoginPage } from './pages/LoginPage';
import { OverviewPage } from './pages/OverviewPage';
import { AgentsPage } from './pages/AgentsPage';
import { PoliciesPage } from './pages/PoliciesPage';
import { LoadingState } from './components/UI';
import { OrganizationSettingsPage } from './pages/DashboardPages';
import { AuditLogsPage } from './pages/AuditLogsPage';
import { NotificationsPage } from './pages/NotificationsPage';
import { DashboardTelemetryPage } from './pages/DashboardTelemetryPage';

function ProtectedLayout() {
  const { session } = useAuth();
  return session ? <AppShell><Outlet /></AppShell> : <Navigate to="/sign-in" replace />;
}

function AuthCallback() {
  const [params] = useSearchParams();
  const navigate = useNavigate();
  const [error, setError] = useState('');
  useEffect(() => {
    const code = params.get('code');
    const state = params.get('state');
    const oauthError = params.get('error_description') || params.get('error');
    if (oauthError) { setError('Sign-in was not completed. Return to the sign-in page to try again.'); return; }
    if (!code || !state) { setError('The sign-in response was incomplete. Please try again.'); return; }
    let active = true;
    finishLogin(code, state).then(() => { if (active) navigate('/', { replace: true }); })
      .catch((reason: unknown) => { if (active) setError(reason instanceof Error ? reason.message : 'Sign-in could not be completed.'); });
    return () => { active = false; };
  }, [navigate, params]);
  if (error) return <LoginPage initialError={error} />;
  return <div className="callback-screen"><div className="brand-mark"><span className="brand-emblem">A</span>AgentShield <b>AI</b></div><LoadingState label="Completing secure sign-in" /></div>;
}

function RoutesView() {
  const { session } = useAuth();
  return <Routes>
    <Route path="/sign-in" element={session ? <Navigate to="/" replace /> : <LoginPage />} />
    <Route path="/auth/callback" element={<AuthCallback />} />
    <Route element={<ProtectedLayout />}>
      <Route index element={<OverviewPage />} />
      <Route path="/agents" element={<AgentsPage />} />
      <Route path="/policies" element={<PoliciesPage />} />
      <Route path="/runtime" element={<DashboardTelemetryPage page="runtime" />} />
      <Route path="/analysis" element={<DashboardTelemetryPage page="analysis" />} />
      <Route path="/trust" element={<DashboardTelemetryPage page="trust" />} />
      <Route path="/audit" element={<AuditLogsPage />} />
      <Route path="/notifications" element={<NotificationsPage />} />
      <Route path="/organization" element={<OrganizationSettingsPage />} />
      <Route path="*" element={<Navigate to="/" replace />} />
    </Route>
  </Routes>;
}

export default function App() {
  return <AuthProvider><RoutesView /></AuthProvider>;
}
