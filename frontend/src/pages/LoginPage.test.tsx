import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { ApiError, api } from '../lib/api';
import { beginLogin } from '../lib/auth';
import { LoginPage } from './LoginPage';

vi.mock('../lib/auth', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../lib/auth')>();
  return { ...actual, beginLogin: vi.fn() };
});
vi.mock('../lib/api', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../lib/api')>();
  return { ...actual, api: { ...actual.api, onboardOrganization: vi.fn() } };
});

const ORG_ID = '123e4567-e89b-42d3-a456-426614174000';
const CREATED_ORG_ID = '123e4567-e89b-42d3-b456-426614174001';
const PASSWORD = 'CorrectHorseBattery1!';

describe('LoginPage', () => {
  beforeEach(() => {
    window.history.replaceState({}, '', '/sign-in');
    window.localStorage.clear();
    document.cookie = 'XSRF-TOKEN=; Max-Age=0; path=/';
    vi.mocked(beginLogin).mockResolvedValue(undefined);
    vi.mocked(api.onboardOrganization).mockResolvedValue({ organizationId: CREATED_ORG_ID });
  });

  it('renders the branded Identity sign-in form with the CSRF cookie and posts directly to Identity', () => {
    document.cookie = 'XSRF-TOKEN=identity-csrf-test; path=/';
    window.history.replaceState({}, '', '/sign-in?identityLogin=1');
    render(<LoginPage />);

    expect(screen.getByRole('heading', { name: 'Sign in to AgentShield AI' })).toBeInTheDocument();
    expect(screen.getByLabelText('Work email')).toHaveAttribute('name', 'username');
    expect(screen.getByLabelText('Password')).toHaveAttribute('name', 'password');
    expect(screen.getByLabelText('Password')).toHaveAttribute('type', 'password');
    const form = screen.getByRole('button', { name: 'Sign in' }).closest('form');
    expect(form).toHaveAttribute('method', 'post');
    expect(form).toHaveAttribute('action', new URL('/login', window.location.origin).toString());
    expect(screen.getByDisplayValue('identity-csrf-test')).toHaveAttribute('name', '_csrf');
    expect(screen.queryByRole('tab', { name: 'Create your organization' })).not.toBeInTheDocument();
    expect(beginLogin).not.toHaveBeenCalled();
  });

  it('blocks Identity sign-in when the CSRF cookie is unavailable', () => {
    window.history.replaceState({}, '', '/sign-in?identityLogin=1');
    render(<LoginPage />);
    expect(screen.getByRole('alert')).toHaveTextContent('secure sign-in form could not be initialized');
    expect(screen.getByRole('button', { name: 'Sign in' })).toBeDisabled();
  });

  it('shows a generic authentication error without revealing account existence', () => {
    window.history.replaceState({}, '', '/sign-in?identityLogin=1&loginError=1');
    document.cookie = 'XSRF-TOKEN=identity-csrf-test; path=/';
    render(<LoginPage />);
    expect(screen.getByRole('alert')).toHaveTextContent('Email or password was not accepted');
  });

  it('shows clear validation when the existing-organization ID is empty or malformed', async () => {
    const user = userEvent.setup();
    render(<LoginPage />);
    const submit = screen.getByRole('button', { name: /continue to sign in/i });
    expect(submit).toBeEnabled();
    await user.click(submit);
    expect(screen.getByRole('alert')).toHaveTextContent('Enter your organization ID');
    await user.type(screen.getByLabelText('Organization ID'), 'not-a-uuid');
    await user.click(submit);
    expect(screen.getByRole('alert')).toHaveTextContent('valid UUID');
    expect(beginLogin).not.toHaveBeenCalled();
  });

  it('submits by keyboard and starts PKCE login for a valid organization UUID', async () => {
    const user = userEvent.setup();
    render(<LoginPage />);
    await user.type(screen.getByLabelText('Organization ID'), ORG_ID);
    await user.keyboard('{Enter}');
    await waitFor(() => expect(beginLogin).toHaveBeenCalledWith(ORG_ID));
  });

  it('remembers only the organization ID when opted in and restores it on the next visit', async () => {
    const user = userEvent.setup();
    const { unmount } = render(<LoginPage />);
    await user.type(screen.getByLabelText('Organization ID'), ORG_ID);
    await user.click(screen.getByRole('checkbox', { name: /remember organization id/i }));
    await user.click(screen.getByRole('button', { name: /continue to sign in/i }));
    expect(window.localStorage.getItem('agentshield.rememberedOrganizationId')).toBe(ORG_ID);
    expect(window.localStorage.getItem('agentshield.rememberedPassword')).toBeNull();

    unmount();
    render(<LoginPage />);
    expect(screen.getByLabelText('Organization ID')).toHaveValue(ORG_ID);
    expect(screen.getByRole('checkbox', { name: /remember organization id/i })).toBeChecked();
  });

  it('clears the remembered organization ID when the option is unchecked', async () => {
    const user = userEvent.setup();
    window.localStorage.setItem('agentshield.rememberedOrganizationId', ORG_ID);
    render(<LoginPage />);
    await user.click(screen.getByRole('checkbox', { name: /remember organization id/i }));
    expect(window.localStorage.getItem('agentshield.rememberedOrganizationId')).toBeNull();
  });

  it('shows a loading state and ignores duplicate submissions', async () => {
    const user = userEvent.setup();
    let finish!: () => void;
    vi.mocked(beginLogin).mockReturnValue(new Promise<void>((resolve) => { finish = resolve; }));
    render(<LoginPage initialOrganizationId={ORG_ID} />);
    const submit = screen.getByRole('button', { name: /continue to sign in/i });
    await user.click(submit);
    expect(submit).toBeDisabled();
    expect(submit).toHaveAttribute('aria-busy', 'true');
    await user.click(submit);
    expect(beginLogin).toHaveBeenCalledTimes(1);
    finish();
  });

  it('shows Identity Service sign-in errors without collecting user passwords', () => {
    render(<LoginPage initialError="Sign-in was not completed. Return to the sign-in page to try again." />);
    expect(screen.getByRole('alert')).toHaveTextContent('Sign-in was not completed');
    expect(document.querySelector('input[type="password"]')).not.toBeInTheDocument();
  });

  it('creates an organization, then shows its ID and continue-to-sign-in action', async () => {
    const user = userEvent.setup();
    render(<LoginPage />);
    await user.click(screen.getByRole('tab', { name: 'Create your organization' }));
    await user.type(screen.getByLabelText('Organization name'), 'Northstar Research');
    await user.type(screen.getByLabelText('First name'), 'Ari');
    await user.type(screen.getByLabelText('Last name'), 'Morgan');
    await user.type(screen.getByLabelText('Work email'), 'ari@example.test');
    await user.type(screen.getByLabelText(/^Password/), PASSWORD);
    await user.click(screen.getByRole('button', { name: 'Create organization' }));
    await screen.findByRole('heading', { name: 'You’re ready to sign in' });
    expect(screen.getByText(CREATED_ORG_ID)).toBeInTheDocument();
    expect(api.onboardOrganization).toHaveBeenCalledWith({
      organizationName: 'Northstar Research', firstName: 'Ari', lastName: 'Morgan',
      email: 'ari@example.test', password: PASSWORD,
    });
    await user.click(screen.getByRole('button', { name: /continue to sign in/i }));
    expect(screen.getByLabelText('Organization ID')).toHaveValue(CREATED_ORG_ID);
  });

  it('shows API conflicts and failures and clears password after the attempt', async () => {
    const user = userEvent.setup();
    vi.mocked(api.onboardOrganization).mockRejectedValue(new ApiError('Organization onboarding could not be completed with the supplied information', 409));
    render(<LoginPage />);
    await user.click(screen.getByRole('tab', { name: 'Create your organization' }));
    await user.type(screen.getByLabelText('Organization name'), 'Northstar Research');
    await user.type(screen.getByLabelText('First name'), 'Ari');
    await user.type(screen.getByLabelText('Last name'), 'Morgan');
    await user.type(screen.getByLabelText('Work email'), 'ari@example.test');
    await user.type(screen.getByLabelText(/^Password/), PASSWORD);
    await user.click(screen.getByRole('button', { name: 'Create organization' }));
    expect(await screen.findByRole('alert')).toHaveTextContent('could not be completed');
    expect(screen.getByLabelText(/^Password/)).toHaveValue('');
  });
});
