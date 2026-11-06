import { useRef, useState, type FormEvent } from 'react';
import { ArrowRight, Check, Copy, Fingerprint, LockKeyhole, ShieldCheck, Sparkles } from 'lucide-react';
import { apiOrigin, beginLogin, isOrganizationId } from '../lib/auth';
import { api } from '../lib/api';
import type { OrganizationOnboardingRequest } from '../types';
import { Button, FormField } from '../components/UI';

type LoginMode = 'existing' | 'create';
type OnboardingFields = OrganizationOnboardingRequest;
const emptyOnboarding: OnboardingFields = { organizationName: '', firstName: '', lastName: '', email: '', password: '' };
const rememberedOrganizationKey = 'agentshield.rememberedOrganizationId';

function readRememberedOrganizationId() {
  try { return window.localStorage.getItem(rememberedOrganizationKey) ?? ''; }
  catch { return ''; }
}

function readCsrfCookie() {
  const cookie = document.cookie.split('; ').find((part) => part.startsWith('XSRF-TOKEN='));
  if (!cookie) return '';
  try { return decodeURIComponent(cookie.slice('XSRF-TOKEN='.length)); }
  catch { return ''; }
}

function IdentityCredentialForm({ loginError }: { loginError: boolean }) {
  const [busy, setBusy] = useState(false);
  const csrfToken = readCsrfCookie();
  return <>
    <div className="login-card-icon"><ShieldCheck size={23} /></div><div className="eyebrow">SECURE AUTHORIZATION</div>
    <h2 id="login-title">Sign in to AgentShield AI</h2>
    <p className="login-card-subtitle">Identity Service will verify your account and resume the requested organization sign-in.</p>
    <form action={new URL('/login', apiOrigin()).toString()} method="post" onSubmit={() => setBusy(true)}>
      <div className="identity-login-fields">
        <FormField label="Work email"><input type="email" name="username" autoComplete="username" required autoFocus /></FormField>
        <FormField label="Password"><input type="password" name="password" autoComplete="current-password" required /></FormField>
      </div>
      <input type="hidden" name="_csrf" value={csrfToken} />
      {!csrfToken && <div role="alert" className="form-error login-error">The secure sign-in form could not be initialized. Return to the organization sign-in page and try again.</div>}
      {loginError && <div role="alert" className="form-error login-error">Email or password was not accepted. Check your credentials and try again.</div>}
      <Button type="submit" className="login-submit" disabled={busy || !csrfToken} aria-busy={busy}>
        {busy ? 'Signing in securely…' : 'Sign in'}{busy ? <span className="button-spinner" aria-hidden="true" /> : <ArrowRight size={17} />}
      </Button>
    </form>
    <div className="login-security-note identity-login-note"><span className="secure-icon"><LockKeyhole size={16} /></span><p>Your credentials are submitted directly to Identity Service. The console does not store your password.</p></div>
    <a className="identity-login-back" href="/sign-in">Return to organization selection</a>
  </>;
}

export function LoginPage({ initialError = '', initialOrganizationId = '' }: { initialError?: string; initialOrganizationId?: string }) {
  const searchParams = new URLSearchParams(window.location.search);
  const identityLogin = searchParams.get('identityLogin') === '1';
  const identityLoginError = searchParams.get('loginError') === '1';
  const [mode, setMode] = useState<LoginMode>('existing');
  const [error, setError] = useState(initialError);
  const [busy, setBusy] = useState(false);
  const [organizationId, setOrganizationId] = useState(initialOrganizationId || readRememberedOrganizationId());
  const [rememberOrganizationId, setRememberOrganizationId] = useState(() => Boolean(readRememberedOrganizationId()));
  const [onboarding, setOnboarding] = useState<OnboardingFields>(emptyOnboarding);
  const [createdOrganizationId, setCreatedOrganizationId] = useState('');
  const busyRef = useRef(false);

  async function submitLogin(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (busyRef.current) return;
    if (!organizationId.trim()) { setError('Enter your organization ID to continue.'); return; }
    if (!isOrganizationId(organizationId)) { setError('Enter a valid UUID, for example xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx.'); return; }
    try {
      if (rememberOrganizationId) window.localStorage.setItem(rememberedOrganizationKey, organizationId.trim());
      else window.localStorage.removeItem(rememberedOrganizationKey);
    } catch { /* Remembering is optional; storage restrictions must not block sign-in. */ }
    busyRef.current = true;
    setError(''); setBusy(true);
    try { await beginLogin(organizationId.trim()); }
    catch (reason) {
      busyRef.current = false; setBusy(false);
      setError(reason instanceof Error ? reason.message : 'Secure sign-in could not be started. Check the API Gateway URL and try again.');
    }
  }

  async function submitOnboarding(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (busyRef.current) return;
    const value = { ...onboarding, organizationName: onboarding.organizationName.trim(), firstName: onboarding.firstName.trim(), lastName: onboarding.lastName.trim(), email: onboarding.email.trim() };
    if (!value.organizationName || !value.firstName || !value.lastName || !value.email || !value.password) { setError('Complete all fields to create your organization.'); return; }
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value.email)) { setError('Enter a valid email address.'); return; }
    if ([...value.password].length < 12 || new TextEncoder().encode(value.password).length > 72) { setError('Use at least 12 characters and no more than 72 UTF-8 bytes for your password.'); return; }
    busyRef.current = true; setError(''); setBusy(true);
    try {
      const result = await api.onboardOrganization(value);
      setCreatedOrganizationId(result.organizationId);
      setOnboarding(emptyOnboarding);
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : 'Organization setup failed. Please try again.');
    } finally {
      busyRef.current = false; setBusy(false);
      setOnboarding((current) => ({ ...current, password: '' }));
    }
  }

  async function copyOrganizationId() {
    try { await navigator.clipboard.writeText(createdOrganizationId); setError('Organization ID copied.'); }
    catch { setError('Copy is unavailable in this browser. Select and copy the organization ID above.'); }
  }

  function chooseMode(next: LoginMode) {
    if (busy) return;
    setMode(next); setError(''); setCreatedOrganizationId('');
  }

  return <div className="login-screen">
    <div className="login-backdrop" aria-hidden="true"><div className="login-grid" /><div className="login-glow login-glow-one" /><div className="login-glow login-glow-two" /></div>
    <header className="login-brand"><span className="brand-emblem">A</span><span>AgentShield <b>AI</b></span><span className="login-brand-divider" /><span className="login-console-label">SECURITY CONSOLE</span></header>
    <main className="login-main">
      <section className="login-message"><div className="login-kicker"><span className="live-dot" /> TRUSTED AI. CONTROLLED.</div>
        <h1>Bring every AI action<br /><em>into the light.</em></h1>
        <p>One clear view of your agents, policies, and security posture. Govern with confidence from the first request to the last event.</p>
        <div className="login-proof"><div><span><Check size={15} /></span>Policy-controlled execution</div><div><span><Check size={15} /></span>Organization-level isolation</div><div><span><Check size={15} /></span>Evidence-rich audit trails</div></div>
        <div className="login-orbit" aria-hidden="true"><div className="orbit orbit-a" /><div className="orbit orbit-b" /><div className="orbit-core"><ShieldCheck size={36} /></div><span className="orbit-node orbit-node-a"><LockKeyhole size={17} /></span><span className="orbit-node orbit-node-b"><Fingerprint size={18} /></span><span className="orbit-node orbit-node-c"><Sparkles size={17} /></span></div>
      </section>
      <section className={`login-card ${mode === 'create' || createdOrganizationId ? 'login-card-onboarding' : ''}`} aria-labelledby="login-title">
        {identityLogin ? <IdentityCredentialForm loginError={identityLoginError} /> : createdOrganizationId ? <div className="onboarding-success" role="status">
          <div className="login-card-icon"><Check size={23} /></div><div className="eyebrow">WORKSPACE CREATED</div><h2 id="login-title">You’re ready to sign in</h2>
          <p className="login-card-subtitle">Your organization and initial OWNER membership were created.</p>
          <div className="created-org-id"><small>ORGANIZATION ID</small><code>{createdOrganizationId}</code><Button type="button" variant="secondary" onClick={() => void copyOrganizationId()} aria-label="Copy organization ID"><Copy size={15} />Copy</Button></div>
          <p className="login-card-subtitle">Save this ID. It is needed when signing in, and Identity Service will verify your membership.</p>
          <Button type="button" className="login-submit" onClick={() => { setOrganizationId(createdOrganizationId); setMode('existing'); setCreatedOrganizationId(''); setError(''); }}>Continue to sign in <ArrowRight size={17} /></Button>
          {error && <div role="status" className="login-feedback">{error}</div>}
        </div> : <>
          <div className="login-card-icon"><ShieldCheck size={23} /></div><div className="eyebrow">IDENTITY FIRST</div>
          <h2 id="login-title">{mode === 'existing' ? 'Welcome back' : 'Create your organization'}</h2>
          <p className="login-card-subtitle">{mode === 'existing' ? 'Continue with your organization account.' : 'Set up a secure workspace and become its first owner.'}</p>
          <div className="login-mode-switch" role="tablist" aria-label="Account setup">
            <button type="button" role="tab" aria-selected={mode === 'existing'} className={mode === 'existing' ? 'selected' : ''} onClick={() => chooseMode('existing')}>Existing organization</button>
            <button type="button" role="tab" aria-selected={mode === 'create'} className={mode === 'create' ? 'selected' : ''} onClick={() => chooseMode('create')}>Create your organization</button>
          </div>
          {mode === 'existing' ? <form onSubmit={(event) => void submitLogin(event)} noValidate>
            <div className="form-field"><label htmlFor="organization-id">Organization ID</label><input id="organization-id" className="text-input" value={organizationId} onChange={(event) => { setOrganizationId(event.target.value); setError(''); }} placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" autoComplete="off" aria-invalid={Boolean(error)} aria-describedby="organization-id-help" /><small id="organization-id-help">Ask your organization owner or admin, or find it in your workspace invitation.</small></div>
            <label className="remember-organization"><input type="checkbox" checked={rememberOrganizationId} onChange={(event) => {
              const checked = event.target.checked;
              setRememberOrganizationId(checked);
              if (!checked) { try { window.localStorage.removeItem(rememberedOrganizationKey); } catch { /* Optional browser storage. */ } }
            }} /><span><strong>Remember organization ID</strong><small>Only this ID is saved on this device. Your password is never saved here.</small></span></label>
            <Button type="submit" className="login-submit" disabled={busy} aria-busy={busy}>{busy ? 'Redirecting securely…' : 'Continue to sign in'}{busy ? <span className="button-spinner" aria-hidden="true" /> : <ArrowRight size={17} />}</Button>
          </form> : <form onSubmit={(event) => void submitOnboarding(event)} noValidate>
            <div className="onboarding-form-grid">
              <FormField label="Organization name"><input required maxLength={150} value={onboarding.organizationName} onChange={(event) => setOnboarding({ ...onboarding, organizationName: event.target.value })} autoComplete="organization" /></FormField>
              <div className="onboarding-name-row">
                <FormField label="First name"><input required maxLength={100} value={onboarding.firstName} onChange={(event) => setOnboarding({ ...onboarding, firstName: event.target.value })} autoComplete="given-name" /></FormField>
                <FormField label="Last name"><input required maxLength={100} value={onboarding.lastName} onChange={(event) => setOnboarding({ ...onboarding, lastName: event.target.value })} autoComplete="family-name" /></FormField>
              </div>
              <FormField label="Work email"><input required type="email" maxLength={254} value={onboarding.email} onChange={(event) => setOnboarding({ ...onboarding, email: event.target.value })} autoComplete="email" /></FormField>
              <FormField label="Password" hint="At least 12 characters; maximum 72 UTF-8 bytes."><input required type="password" value={onboarding.password} onChange={(event) => setOnboarding({ ...onboarding, password: event.target.value })} autoComplete="new-password" /></FormField>
            </div>
            <p className="onboarding-owner-note"><ShieldCheck size={15} />You will be added as this new organization’s initial OWNER. Roles cannot be self-assigned in existing organizations.</p>
            <Button type="submit" className="login-submit" disabled={busy} aria-busy={busy}>{busy ? 'Creating secure workspace…' : 'Create organization'}{busy ? <span className="button-spinner" aria-hidden="true" /> : <ArrowRight size={17} />}</Button>
          </form>}
          {error && <div id="login-feedback" role="alert" className="form-error login-error">{error}</div>}
          <div className="login-divider"><span /> <small>SECURE AUTHORIZATION</small> <span /></div>
          <div className="login-security-note"><span className="secure-icon"><LockKeyhole size={16} /></span><p>{mode === 'existing' ? 'Your email and password are entered on the Identity Service sign-in page. This console never collects or stores your password.' : 'Your password is sent directly to Identity Service over the configured API Gateway and is never saved in browser storage.'}</p></div>
          <div className="login-flow-note"><span className="flow-step">01</span><div><strong>{mode === 'existing' ? 'Protected with OAuth 2.0 + PKCE' : 'Organization and OWNER created together'}</strong><small>{mode === 'existing' ? 'Short-lived access token · no browser client secret' : 'Atomic setup · membership checked at sign-in'}</small></div></div>
        </>}
        <div className="login-card-footer"><span><i />Encrypted connection</span><span>Identity Service protected</span></div>
      </section>
    </main>
    <footer className="login-footer"><span>© {new Date().getFullYear()} AgentShield AI</span><span>Security is built into every request.</span><span>Identity Service protected</span></footer>
  </div>;
}
