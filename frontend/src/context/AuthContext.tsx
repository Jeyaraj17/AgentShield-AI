import { useEffect, useMemo, useState, type ReactNode } from 'react';
import { getSession, logout, subscribeAuth, type AuthSession } from '../lib/auth';
import { AuthContext } from './auth-context';
export function AuthProvider({ children }: { children: ReactNode }) {
  const [session, setSession] = useState<AuthSession | null>(getSession());
  useEffect(() => subscribeAuth(setSession), []);
  useEffect(() => {
    const expired = () => setSession(null);
    window.addEventListener('agentshield:unauthorized', expired);
    return () => window.removeEventListener('agentshield:unauthorized', expired);
  }, []);
  const value = useMemo(() => ({ session, signOut: logout }), [session]);
  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}
