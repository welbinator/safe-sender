import { useSearchParams } from 'react-router-dom';
import styles from './Login.module.css';

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
  ms_missing_params: 'Sign-in link was malformed. Please try again.',
  ms_state_missing: 'Session expired before sign-in completed. Please try again.',
  ms_state_invalid: 'Sign-in token was invalid or expired. Please try again.',
  ms_state_mismatch: 'Sign-in token did not match. Please try again.',
  ms_token_exchange_failed: 'Could not reach Microsoft to complete sign-in.',
  ms_no_access_token: 'Microsoft did not return an access token.',
  ms_userinfo_failed: 'Could not retrieve your Microsoft account info.',
  ms_no_email: 'Your Microsoft account did not provide an email address.',
  ms_account_conflict: 'This email is already registered. Try signing in with Google.',
  ms_login_failed: 'Microsoft sign-in failed. Please try again.',
};

export default function Login() {
  const [params] = useSearchParams();
  const errorCode = params.get('error');
  const errorMsg = errorCode ? (ERROR_MESSAGES[errorCode] || `Sign-in failed (${errorCode}).`) : null;

  const returnTo = params.get('return_to') || '/';
  const googleStartUrl = `/api/auth/google/start?return_to=${encodeURIComponent(returnTo)}`;
  const msStartUrl = `/api/auth/microsoft/start?return_to=${encodeURIComponent(returnTo)}`;

  return (
    <div className={styles.page}>
      <div className={styles.card}>
        <div className={styles.logo}>🛡️</div>
        <h1 className={styles.brand}>Sender Safety</h1>
        <p className={styles.tagline}>Outbound email filtering for Google Workspace and Microsoft 365</p>

        <a href={googleStartUrl} className={styles.googleBtn}>
          <span className={styles.googleIcon} aria-hidden="true">G</span>
          <span>Sign in with Google</span>
        </a>

        <a href={msStartUrl} className={styles.msBtn}>
          <span className={styles.msIcon} aria-hidden="true">⊞</span>
          <span>Sign in with Microsoft</span>
        </a>

        {errorMsg && (
          <p className={styles.warn} role="alert">{errorMsg}</p>
        )}
      </div>
    </div>
  );
}
