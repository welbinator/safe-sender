import { useState } from 'react';
import { NavLink, Outlet, useNavigate } from 'react-router-dom';
import { useAuth } from '../AuthContext';
import widgetRegistry from '../widgetRegistry';
import styles from './Layout.module.css';

export default function Layout() {
  const { customer, logout } = useAuth();
  const navigate = useNavigate();
  const [drawerOpen, setDrawerOpen] = useState(false);

  const handleLogout = () => { logout(); navigate('/login'); };
  const closeDrawer = () => setDrawerOpen(false);

  const NavItems = ({ onClick }) => (
    <>
      {widgetRegistry.map(w => (
        <NavLink
          key={w.id}
          to={w.route}
          end={w.route === '/'}
          onClick={onClick}
          className={({ isActive }) => `${styles.navItem} ${isActive ? styles.active : ''}`}
        >
          {w.label}
        </NavLink>
      ))}
    </>
  );

  return (
    <div className={styles.shell}>

      {/* Desktop sidebar */}
      <aside className={styles.sidebar}>
        <div className={styles.brand}>
          <span className={styles.logo}>🛡️</span>
          <span>Sender Safety</span>
        </div>
        <nav className={styles.nav}>
          <NavItems />
        </nav>
        <div className={styles.footer}>
          <div className={styles.user}>{customer?.email}</div>
          <button onClick={handleLogout} className={styles.logoutBtn}>Sign out</button>
        </div>
      </aside>

      {/* Mobile top bar */}
      <div className={styles.mobileBar}>
        <div className={styles.mobileBrand}>
          <span>🛡️</span>
          <span>Sender Safety</span>
        </div>
        <button className={styles.hamburger} onClick={() => setDrawerOpen(true)} aria-label="Open menu">
          ☰
        </button>
      </div>

      {/* Mobile overlay + drawer */}
      {drawerOpen && (
        <div className={styles.overlay} onClick={closeDrawer}>
          <nav className={`${styles.drawer} ${styles.drawerOpen}`} onClick={e => e.stopPropagation()}>
            <div className={styles.drawerHeader}>
              <div className={styles.drawerBrand}>
                <span>🛡️</span>
                <span>Sender Safety</span>
              </div>
              <button className={styles.closeBtn} onClick={closeDrawer} aria-label="Close menu">✕</button>
            </div>
            <div className={styles.drawerNav}>
              <NavItems onClick={closeDrawer} />
            </div>
            <div className={styles.drawerFooter}>
              <div className={styles.user}>{customer?.email}</div>
              <button onClick={() => { closeDrawer(); handleLogout(); }} className={styles.logoutBtn}>Sign out</button>
            </div>
          </nav>
        </div>
      )}

      {/* Main content */}
      <main className={styles.main}>
        <Outlet />
      </main>

    </div>
  );
}
