import { useEffect, useRef, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../AuthContext';
import { authGoogle } from '../api';
import SmtpWelcomeModal from '../components/SmtpWelcomeModal';
import styles from './Login.module.css';

const GOOGLE_CLIENT_ID = import.meta.env.VITE_GOOGLE_CLIENT_ID || '';

function initGoogleButton(btnRef, onCredential) {
  window.google.accounts.id.initialize({
    client_id: GOOGLE_CLIENT_ID,
    callback: onCredential,
  });
  window.google.accounts.id.renderButton(btnRef.current, {
    theme: 'outline',
    size: 'large',
    text: 'signin_with',
  });
}

export default function Login() {
  const { login, customer } = useAuth();
  const navigate = useNavigate();
  const btnRef = useRef(null);
  const [smtpCreds, setSmtpCreds] = useState(null);

  useEffect(() => {
    if (!GOOGLE_CLIENT_ID) return;

    const onCredential = async ({ credential }) => {
      try {
        const res = await authGoogle(credential);
        login(res.data.access_token, { id: res.data.customer_id, email: res.data.email });
        if (res.data.is_new && res.data.smtp_username && res.data.smtp_password) {
          setSmtpCreds({ username: res.data.smtp_username, password: res.data.smtp_password });
        } else {
          navigate('/');
        }
      } catch (err) {
        console.error('Login failed', err);
        alert(err.response?.data?.detail || 'Login failed. Make sure you have a Google Workspace account.');
      }
    };

    if (window.google?.accounts) {
      // Script already loaded
      initGoogleButton(btnRef, onCredential);
    } else {
      // Wait for script to load
      // Find the GSI script by iterating (querySelector with slashes in attr value is tricky)
      const scripts = Array.from(document.querySelectorAll('script[src]'));
      const existing = scripts.find(s => s.src && s.src.includes('accounts.google.com/gsi/client'));
      if (existing) {
        existing.addEventListener('load', () => initGoogleButton(btnRef, onCredential));
      }
    }
  }, [customer, smtpCreds]);

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

      {smtpCreds && (
        <SmtpWelcomeModal
          username={smtpCreds.username}
          password={smtpCreds.password}
          onDone={() => { setSmtpCreds(null); navigate('/'); }}
        />
      )}
    </div>
  );
}
