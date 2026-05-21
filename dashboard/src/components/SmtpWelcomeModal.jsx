import { useState } from 'react';
import { rotateSmtpCredentials } from '../api';
import styles from './SmtpWelcomeModal.module.css';

// Sprint B C13: the server no longer emits the plaintext SMTP password as
// part of /auth/google. Instead, this modal exposes a "Generate password"
// button that calls POST /customers/me/smtp-credentials/rotate. The
// plaintext is returned exactly once in the response body and shown here;
// it's never persisted client-side. Rotating again invalidates this one.
export default function SmtpWelcomeModal({ onDone }) {
  const [creds, setCreds] = useState(null); // {username, password}
  const [generating, setGenerating] = useState(false);
  const [error, setError] = useState(null);
  const [copied, setCopied] = useState({});

  const generate = async () => {
    setGenerating(true);
    setError(null);
    try {
      const r = await rotateSmtpCredentials();
      setCreds({ username: r.data.smtp_username, password: r.data.smtp_password });
    } catch (e) {
      setError(e.response?.data?.detail || 'Could not generate credentials. Try again.');
    } finally {
      setGenerating(false);
    }
  };

  const copy = (key, value) => {
    navigator.clipboard.writeText(value);
    setCopied(c => ({ ...c, [key]: true }));
    setTimeout(() => setCopied(c => ({ ...c, [key]: false })), 2000);
  };

  const fields = creds ? [
    { key: 'host',     label: 'SMTP Host', value: 'smtp.sendersafety.com' },
    { key: 'port',     label: 'Port',      value: '587' },
    { key: 'username', label: 'Username',  value: creds.username },
    { key: 'password', label: 'Password',  value: creds.password },
  ] : [];

  return (
    <div className={styles.overlay}>
      <div className={styles.modal}>
        <div className={styles.icon}>🔐</div>
        <h2 className={styles.title}>Generate SMTP Credentials</h2>

        {!creds && (
          <>
            <p className={styles.subtitle}>
              Click below to generate your one-time SMTP password. We'll show it
              <strong> exactly once</strong> — copy it before closing this dialog.
              You can always rotate it later from your dashboard.
            </p>
            {error && <p className={styles.warn}>{error}</p>}
            <button
              className={styles.doneBtn}
              onClick={generate}
              disabled={generating}
            >
              {generating ? 'Generating…' : 'Generate password'}
            </button>
            <button
              className={styles.linkBtn}
              onClick={onDone}
              style={{ marginTop: 12, background: 'none', border: 'none', color: '#888', cursor: 'pointer' }}
            >
              Skip for now
            </button>
          </>
        )}

        {creds && (
          <>
            <p className={styles.subtitle}>
              Copy these now — the password <strong>won't be shown again</strong>.
              You'll need them to configure your Google Workspace outbound gateway.
            </p>
            <div className={styles.fields}>
              {fields.map(({ key, label, value }) => (
                <div key={key} className={styles.field}>
                  <span className={styles.label}>{label}</span>
                  <div className={styles.row}>
                    <code className={styles.value}>{value}</code>
                    <button
                      className={styles.copyBtn}
                      onClick={() => copy(key, value)}
                    >
                      {copied[key] ? '✓ Copied' : 'Copy'}
                    </button>
                  </div>
                </div>
              ))}
            </div>
            <p className={styles.note}>
              You can rotate your password anytime from the <strong>SMTP Credentials</strong> widget on your dashboard.
            </p>
            <button className={styles.doneBtn} onClick={onDone}>
              I've saved my credentials →
            </button>
          </>
        )}
      </div>
    </div>
  );
}
