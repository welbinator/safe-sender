import { useState } from 'react';
import styles from './SmtpWelcomeModal.module.css';

export default function SmtpWelcomeModal({ username, password, onDone }) {
  const [copied, setCopied] = useState({});

  const copy = (key, value) => {
    navigator.clipboard.writeText(value);
    setCopied(c => ({ ...c, [key]: true }));
    setTimeout(() => setCopied(c => ({ ...c, [key]: false })), 2000);
  };

  const fields = [
    { key: 'host',     label: 'SMTP Host',     value: 'smtp.sendersafety.com' },
    { key: 'port',     label: 'Port',           value: '587' },
    { key: 'username', label: 'Username',       value: username },
    { key: 'password', label: 'Password',       value: password },
  ];

  return (
    <div className={styles.overlay}>
      <div className={styles.modal}>
        <div className={styles.icon}>🔐</div>
        <h2 className={styles.title}>Your SMTP Credentials</h2>
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
      </div>
    </div>
  );
}
