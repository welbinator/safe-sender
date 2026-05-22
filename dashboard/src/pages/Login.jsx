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
  // Sprint B C13: server no longer returns smtp_password at signup. New
  // users see a "Generate SMTP password" prompt that calls the rotate
  // endpoint on demand. We just track whether this signup is a brand-new
  // account so we can route accordingly.
  const [showSmtpSetup, setShowSmtpSetup] = useState(false);

  useEffect(() => {
    if (!GOOGLE_CLIENT_ID) return;

    const onCredential = async ({ credential }) => {
      try {
        const res = await authGoogle(credential);
        // Cookie is already set by the server. F-43: refetch /customers/me
        // instead of trusting the response payload — guarantees the cookie
        // round-trips and gives us the canonical server view.
        await login();
        if (res.data.is_new) {
          setShowSmtpSetup(true);
        } else {
          navigate('/');
        }
      } catch (err) {
        console.error('Login failed', err);
        alert(err.response?.data?.detail || 'Login failed. Make sure you have a Google Workspace account.');
      }
    };

    // The GIS script is loaded statically from index.html (Sprint B C14).
    // It usually arrives before React mounts; if not, poll briefly.
    const start = Date.now();
    const tryInit = () => {
      if (window.google?.accounts?.id) {
        initGoogleButton(btnRef, onCredential);
      } else if (Date.now() - start < 5000) {
        setTimeout(tryInit, 100);
      }
    };
    tryInit();
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

      {showSmtpSetup && (
        <SmtpWelcomeModal
          onDone={() => { setShowSmtpSetup(false); navigate('/'); }}
        />
      )}
    </div>
  );
}
