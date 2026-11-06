import { describe, expect, it } from 'vitest';
import { buildAuthorizationUrl, isOrganizationId } from './auth';

describe('organization-scoped PKCE authorization', () => {
  it('accepts UUIDs and rejects empty or malformed organization IDs', () => {
    expect(isOrganizationId('123e4567-e89b-42d3-a456-426614174000')).toBe(true);
    expect(isOrganizationId('')).toBe(false);
    expect(isOrganizationId('not-a-uuid')).toBe(false);
  });

  it('includes the verified-by-Identity tenant selector and mandatory S256 PKCE parameters', () => {
    const url = new URL(buildAuthorizationUrl('123e4567-e89b-42d3-a456-426614174000', 'test-state', 'test-challenge'));
    expect(url.pathname).toBe('/oauth2/authorize');
    expect(url.searchParams.get('organization_id')).toBe('123e4567-e89b-42d3-a456-426614174000');
    expect(url.searchParams.get('code_challenge_method')).toBe('S256');
    expect(url.searchParams.get('reauthenticate')).toBe('true');
    expect(url.searchParams.get('state')).toBe('test-state');
    expect(url.searchParams.get('code_challenge')).toBe('test-challenge');
  });
});
