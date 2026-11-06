import { render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import { Button } from './UI';

describe('Button', () => {
  it('keeps variant styling when a page adds a custom class', () => {
    render(<Button className="login-submit">Continue to sign in</Button>);

    expect(screen.getByRole('button', { name: 'Continue to sign in' }))
      .toHaveClass('button', 'button-primary', 'login-submit');
  });

  it('keeps the selected variant and disabled state together', () => {
    render(<Button variant="secondary" className="toolbar-action" disabled>Cancel</Button>);

    expect(screen.getByRole('button', { name: 'Cancel' }))
      .toHaveClass('button', 'button-secondary', 'toolbar-action');
    expect(screen.getByRole('button', { name: 'Cancel' })).toBeDisabled();
  });
});
