import { createContext, useContext, useState, useEffect } from 'react';
import { getMe, authLogout } from './api';

// Sprint B C13: cookie-based auth. We don't hold the JWT — it lives in an
// HttpOnly cookie. To check whether we're logged in, we just call /me and
// see whether it returns 200 or 401. No localStorage, no token state.

const AuthContext = createContext(null);

export function AuthProvider({ children }) {
  const [customer, setCustomer] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    getMe()
      .then(r => setCustomer(r.data))
      .catch(() => setCustomer(null))
      .finally(() => setLoading(false));
  }, []);

  // F-41: when the API layer sees a 401 on any non-/me request, it dispatches
  // 'auth:unauthorized'. We react by clearing customer state — the RequireAuth
  // guard in App.jsx then redirects via <Navigate>, preserving router state
  // and avoiding the hard `window.location.href` reload from inside an HTTP
  // interceptor.
  useEffect(() => {
    const onUnauthorized = () => setCustomer(null);
    window.addEventListener('auth:unauthorized', onUnauthorized);
    return () => window.removeEventListener('auth:unauthorized', onUnauthorized);
  }, []);

  // login() is called by the Google callback AFTER the server set the cookie.
  // F-43: don't trust the payload echoed by /auth/google — re-fetch /me so
  // we know the cookie actually round-trips AND we have the canonical
  // server view of the customer (no client/server drift on plan, status,
  // etc.). If the refetch fails, treat the login as failed.
  const login = async () => {
    const r = await getMe();
    setCustomer(r.data);
    return r.data;
  };

  const logout = async () => {
    try { await authLogout(); } catch (_) { /* best-effort */ }
    setCustomer(null);
    window.location.href = '/login';
  };

  return (
    <AuthContext.Provider value={{ customer, loading, login, logout }}>
      {children}
    </AuthContext.Provider>
  );
}

export const useAuth = () => useContext(AuthContext);
