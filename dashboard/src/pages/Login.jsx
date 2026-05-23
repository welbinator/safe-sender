import { useSearchParams } from 'react-router-dom';
import styles from './Login.module.css';

// F-57: server-side OAuth redirect flow. No GIS popup, no 3rd-party JS, no
// inline handlers. The "Sign in with Google" button is a plain <a href> that
// hits the backend, which 302s to Google with state+PKCE in an HttpOnly
// cookie. On success, Google → /auth/google/callback → /(?new=1) and the
// session cookie is set. On failure, Google → /auth/google/callback →
// /login?error=<code> and we render the error below.
//
// Dropping the GIS popup also lets us strip accounts.google.com and the
// 'unsafe-inline' style-src allowance from CSP — that's the security win.

const ERROR_MESSAGES = {
  access_denied: 'Sign-in was cancelled.',
  missing_params: 'Sign-in link was malformed. Please try again.',
  state_missing: 'Session expired before sign-in completed. Please try again.',
  state_invalid: 'Sign-in token was invalid or expired. Please try again.',
  state_mismatch: 'Sign-in token did not match. Please try again.',
  token_exchange_failed: 'Could not reach Google to complete sign-in.',
  no_id_token: 'Google did not return a sign-in token.',
  bad_token: 'Google sign-in token was rejected.',
  not_workspace: 'Sender Safety requires a Google Workspace account.',
  domain_conflict: 'This domain is already registered to another account.',
  login_failed: 'Sign-in failed. Please try again.',
};

export default function Login() {
  const [params] = useSearchParams();
  const errorCode = params.get('error');
  const errorMsg = errorCode ? (ERROR_MESSAGES[errorCode] || `Sign-in failed (${errorCode}).`) : null;

  // Preserve where the user was trying to go so the callback can land them
  // back there. Defaults to '/' on the server side if absent or unsafe.
  const returnTo = params.get('return_to') || '/';
  const startUrl = `/api/auth/google/start?return_to=${encodeURIComponent(returnTo)}`;

  return (
    <div className={styles.page}>
      <div className={styles.card}>
        <div className={styles.logo}>🛡️</div>
        <h1 className={styles.brand}>Sender Safety</h1>
        <p className={styles.tagline}>Outbound email filtering for Google Workspace</p>

        {/* Plain <a> — browser handles the navigation. No JS, no popup. */}
        <a href={startUrl} className={styles.googleBtn}>
          <span className={styles.googleIcon} aria-hidden="true">G</span>
          <span>Sign in with Google</span>
        </a>

        {errorMsg && (
          <p className={styles.warn} role="alert">{errorMsg}</p>
        )}
      </div>
    </div>
  );
}
