
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { AuthProvider, useAuth } from './AuthContext';
import Login from './pages/Login';
import Layout from './pages/Layout';
import widgetRegistry from './widgetRegistry';

function RequireAuth({ children }) {
  const { customer, loading } = useAuth();
  if (loading) return <div style={{display:'flex',alignItems:'center',justifyContent:'center',height:'100vh',color:'#718096'}}>Loading…</div>;
  if (!customer) return <Navigate to="/login" replace />;
  return children;
}

export default function App() {
  return (
    <AuthProvider>
      <BrowserRouter>
        <Routes>
          <Route path="/login" element={<Login />} />
          <Route path="/" element={<RequireAuth><Layout /></RequireAuth>}>
            {widgetRegistry.map(w => (
              <Route
                key={w.id}
                path={w.route === '/' ? undefined : w.route.slice(1)}
                index={w.route === '/'}
                element={<w.Component />}
              />
            ))}
          </Route>
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </BrowserRouter>
    </AuthProvider>
  );
}
