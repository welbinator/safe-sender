
import { NavLink, Outlet, useNavigate } from 'react-router-dom';
import { useAuth } from '../AuthContext';
import widgetRegistry from '../widgetRegistry';
import styles from './Layout.module.css';

export default function Layout() {
  const { customer, logout } = useAuth();
  const navigate = useNavigate();

  const handleLogout = () => {
    logout();
    navigate('/login');
  };

  return (
    <div className={styles.shell}>
      <aside className={styles.sidebar}>
        <div className={styles.brand}>
          <span className={styles.logo}>🛡️</span>
          <span>Sender Safety</span>
        </div>
        <nav className={styles.nav}>
          {widgetRegistry.map(w => (
            <NavLink
              key={w.id}
              to={w.route}
              end={w.route === '/'}
              className={({ isActive }) => `${styles.navItem} ${isActive ? styles.active : ''}`}
            >
              {w.label}
            </NavLink>
          ))}
        </nav>
        <div className={styles.footer}>
          <div className={styles.user}>{customer?.email}</div>
          <button onClick={handleLogout} className={styles.logoutBtn}>Sign out</button>
        </div>
      </aside>
      <main className={styles.main}>
        <Outlet />
      </main>
    </div>
  );
}
