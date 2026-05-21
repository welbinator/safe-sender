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

  // login() is called by the Google callback AFTER the server set the cookie.
  const login = (customerData) => {
    setCustomer(customerData);
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
