import { createContext, useContext } from 'react';
import type { AuthSession } from '../lib/auth';

export interface AuthValue { session: AuthSession | null; signOut: () => void; }
export const AuthContext = createContext<AuthValue | null>(null);

export function useAuth() {
  const value = useContext(AuthContext);
  if (!value) throw new Error('useAuth must be used inside AuthProvider');
  return value;
}
