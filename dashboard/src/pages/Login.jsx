
import { useEffect, useRef } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../AuthContext';
import { authGoogle } from '../api';
import styles from './Login.module.css';

const GOOGLE_CLIENT_ID = import.meta.env.VITE_GOOGLE_CLIENT_ID || '';

export default function Login() {
  const { login, customer } = useAuth();
  const navigate = useNavigate();
  const btnRef = useRef(null);

  useEffect(() => {
    if (customer) { navigate('/'); return; }
    if (!GOOGLE_CLIENT_ID) return;

    window.google?.accounts.id.initialize({
      client_id: GOOGLE_CLIENT_ID,
      callback: async ({ credential }) => {
        try {
          const res = await authGoogle(credential);
          login(res.data.access_token, res.data.customer);
          navigate('/');
        } catch (err) {
          console.error('Login failed', err);
          alert(err.response?.data?.detail || 'Login failed. Make sure you have a Google Workspace account.');
        }
      },
    });

    window.google?.accounts.id.renderButton(btnRef.current, {
      theme: 'outline',
      size: 'large',
      text: 'signin_with',
    });
  }, [customer]);

  return (
    <div className={styles.page}>
      <div className={styles.card}>
        <div className={styles.logo}>🛡️</div>
        <h1 className={styles.brand}>Sender Safety</h1>
        <p className={styles.tagline}>Outbound email filtering for Google Workspace</p>
        <div ref={btnRef} className={styles.btn} />
        {!GOOGLE_CLIENT_ID && (
          <p className={styles.warn}>⚠ VITE_GOOGLE_CLIENT_ID not set</p>
        )}
      </div>
    </div>
  );
}
