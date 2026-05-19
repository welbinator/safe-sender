
import { createContext, useContext, useState, useEffect } from 'react';
import { getMe } from './api';

const AuthContext = createContext(null);

export function AuthProvider({ children }) {
  const [customer, setCustomer] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const token = localStorage.getItem('token');
    if (!token) { setLoading(false); return; }
    getMe()
      .then(r => setCustomer(r.data))
      .catch(() => localStorage.removeItem('token'))
      .finally(() => setLoading(false));
  }, []);

  const login = (token, customerData) => {
    localStorage.setItem('token', token);
    setCustomer(customerData);
  };

  const logout = () => {
    localStorage.removeItem('token');
    setCustomer(null);
  };

  return (
    <AuthContext.Provider value={{ customer, loading, login, logout }}>
      {children}
    </AuthContext.Provider>
  );
}

export const useAuth = () => useContext(AuthContext);
