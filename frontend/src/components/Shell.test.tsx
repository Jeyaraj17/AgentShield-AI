import { fireEvent, render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { AppShell } from './Shell';

vi.mock('../context/auth-context', () => ({
  useAuth: () => ({ session: null, signOut: vi.fn() }),
}));

vi.mock('../lib/api', () => ({ api: { me: vi.fn() } }));

describe('AppShell sidebar', () => {
  beforeEach(() => {
    vi.stubGlobal('matchMedia', () => ({ matches: false, addEventListener: vi.fn(), removeEventListener: vi.fn() }));
  });

  it('keeps collapse and expand available across navigation changes', async () => {
    const user = userEvent.setup();
    render(<MemoryRouter initialEntries={['/']}><Routes><Route path="*" element={<AppShell><main>Page content</main></AppShell>} /></Routes></MemoryRouter>);

    const collapse = screen.getByRole('button', { name: 'Collapse sidebar' });
    await user.click(collapse);
    expect(screen.getByRole('button', { name: 'Expand sidebar' })).toHaveAttribute('aria-expanded', 'false');

    const agentsLink = document.querySelector<HTMLAnchorElement>('a[title="AI Agents"]');
    expect(agentsLink).not.toBeNull();
    fireEvent.click(agentsLink!);
    expect(screen.getAllByText('AI Agents')).toHaveLength(2);
    expect(screen.getByRole('button', { name: 'Expand sidebar' })).toBeInTheDocument();

    await user.click(screen.getByRole('button', { name: 'Expand sidebar' }));
    expect(screen.getByRole('button', { name: 'Collapse sidebar' })).toHaveAttribute('aria-expanded', 'true');
    await user.click(screen.getByRole('button', { name: 'Collapse sidebar' }));
    expect(screen.getByRole('button', { name: 'Expand sidebar' })).toBeInTheDocument();
  });
});
