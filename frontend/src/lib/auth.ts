import type { UserClaims } from '../types';

const apiBase = import.meta.env.VITE_API_BASE_URL || window.location.origin;
const clientId = import.meta.env.VITE_AUTH_CLIENT_ID || 'agentshield-react-spa';
const redirectUri = import.meta.env.VITE_AUTH_REDIRECT_URI || `${window.location.origin}/auth/callback`;
const verifierKey = 'agentshield.oauth.verifier';
const stateKey = 'agentshield.oauth.state';

export interface AuthSession { accessToken: string; claims: UserClaims; }
export type AuthListener = (session: AuthSession | null) => void;
let session: AuthSession | null = null;
const listeners = new Set<AuthListener>();

function notify() { listeners.forEach((listener) => listener(session)); }
export function getSession() { return session; }
export function subscribeAuth(listener: AuthListener) { listeners.add(listener); return () => { listeners.delete(listener); }; }
export function setSession(next: AuthSession | null) { session = next; notify(); }

function toBase64Url(bytes: Uint8Array) {
  let binary = '';
  bytes.forEach((byte) => { binary += String.fromCharCode(byte); });
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}
function randomString(byteLength = 48) {
  const bytes = crypto.getRandomValues(new Uint8Array(byteLength));
  return toBase64Url(bytes);
}
async function challengeFor(verifier: string) {
  return toBase64Url(new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier))));
}
function decodeClaims(token: string): UserClaims {
  const part = token.split('.')[1];
  if (!part) throw new Error('Identity Service returned an invalid access token.');
  const padded = part.replace(/-/g, '+').replace(/_/g, '/').padEnd(Math.ceil(part.length / 4) * 4, '=');
  return JSON.parse(atob(padded)) as UserClaims;
}

export function isOrganizationId(value: string) {
  return /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(value.trim());
}

export function buildAuthorizationUrl(organizationId: string, state: string, challenge: string) {
  if (!isOrganizationId(organizationId)) throw new Error('Enter a valid organization ID to continue.');
  const url = new URL('/oauth2/authorize', apiBase);
  url.search = new URLSearchParams({
    response_type: 'code', client_id: clientId, redirect_uri: redirectUri,
    scope: 'agentshield.api', organization_id: organizationId.trim(), state,
    code_challenge: challenge, code_challenge_method: 'S256', reauthenticate: 'true',
  }).toString();
  return url.toString();
}

export async function beginLogin(organizationId: string) {
  if (!isOrganizationId(organizationId)) throw new Error('Enter a valid organization ID to continue.');
  const verifier = randomString();
  const state = randomString(32);
  sessionStorage.setItem(verifierKey, verifier);
  sessionStorage.setItem(stateKey, state);
  const challenge = await challengeFor(verifier);
  window.location.assign(buildAuthorizationUrl(organizationId, state, challenge));
}

export async function finishLogin(code: string, returnedState: string): Promise<AuthSession> {
  const expectedState = sessionStorage.getItem(stateKey);
  const verifier = sessionStorage.getItem(verifierKey);
  sessionStorage.removeItem(stateKey);
  sessionStorage.removeItem(verifierKey);
  if (!expectedState || returnedState !== expectedState || !verifier) throw new Error('The sign-in request could not be verified. Please try again.');
  const body = new URLSearchParams({
    grant_type: 'authorization_code', client_id: clientId, redirect_uri: redirectUri,
    code, code_verifier: verifier,
  });
  const response = await fetch(new URL('/oauth2/token', apiBase), {
    method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded', Accept: 'application/json' }, body,
  });
  if (!response.ok) throw new Error('Identity Service could not complete sign-in. Please try again.');
  const data = await response.json() as { access_token: string; token_type: string; expires_in: number };
  if (!data.access_token) throw new Error('Identity Service did not return an access token.');
  const claims = decodeClaims(data.access_token);
  if (claims.exp * 1000 <= Date.now() || !claims.organization_id || !claims.user_id || !claims.organization_role) {
    throw new Error('The access token is expired or does not include an organization context.');
  }
  const next = { accessToken: data.access_token, claims };
  setSession(next);
  return next;
}

export function logout() {
  setSession(null);
  sessionStorage.removeItem(verifierKey);
  sessionStorage.removeItem(stateKey);
}

export function apiOrigin() { return apiBase; }
