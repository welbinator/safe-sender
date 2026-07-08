import { useEffect, useState } from 'react';
import {
  getAiStatus, getAiPolicies, createAiPolicy, deleteAiPolicy,
  enableAiScan, disableAiScan,
} from '../api';
import { extractErrorMessage } from '../errors';
import styles from './AiPolicies.module.css';

export default function AiPolicies() {
  const [status, setStatus] = useState({ ai_scan_enabled: false, policy_count: 0 });
  const [policies, setPolicies] = useState([]);
  const [text, setText] = useState('');
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [toggling, setToggling] = useState(false);
  const [error, setError] = useState('');

  const load = async () => {
    try {
      const [s, p] = await Promise.all([getAiStatus(), getAiPolicies()]);
      setStatus(s.data);
      setPolicies(p.data);
    } catch (err) {
      setError(extractErrorMessage(err, 'Failed to load AI settings'));
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { load(); }, []);

  const handleAdd = async (e) => {
    e.preventDefault();
    if (!text.trim()) return;
    setSaving(true);
    setError('');
    try {
      await createAiPolicy(text.trim());
      setText('');
      await load();
    } catch (err) {
      setError(extractErrorMessage(err, 'Failed to add policy'));
    } finally {
      setSaving(false);
    }
  };

  const handleDelete = async (id) => {
    if (!confirm('Remove this policy?')) return;
    try {
      await deleteAiPolicy(id);
      await load();
    } catch (err) {
      setError(extractErrorMessage(err, 'Failed to delete policy'));
    }
  };

  const handleToggle = async () => {
    setToggling(true);
    setError('');
    try {
      if (status.ai_scan_enabled) {
        await disableAiScan();
      } else {
        await enableAiScan();
      }
      await load();
    } catch (err) {
      setError(extractErrorMessage(err, 'Failed to update AI status'));
    } finally {
      setToggling(false);
    }
  };

  if (loading) return <div className={styles.loading}>Loading…</div>;

  return (
    <div className={styles.container}>
      <div className={styles.header}>
        <div>
          <h1 className={styles.title}>AI Compliance Scanning</h1>
          <p className={styles.subtitle}>
            Write plain-English policies. The AI scans every outbound email and blocks anything
            that violates them — even phrasing your keyword rules would miss.
          </p>
        </div>
        <div className={styles.toggleBlock}>
          <span className={`${styles.badge} ${status.ai_scan_enabled ? styles.badgeOn : styles.badgeOff}`}>
            {status.ai_scan_enabled ? 'Enabled' : 'Disabled'}
          </span>
          <button
            className={`${styles.toggleBtn} ${status.ai_scan_enabled ? styles.toggleOff : styles.toggleOn}`}
            onClick={handleToggle}
            disabled={toggling}
          >
            {toggling ? '…' : status.ai_scan_enabled ? 'Disable AI Scan' : 'Enable AI Scan'}
          </button>
        </div>
      </div>

      {error && <div className={styles.error}>{error}</div>}
      {status.ai_scan_enabled && policies.length === 0 && (
        <div className={styles.warning}>AI Scan is enabled but you have no policies yet — add at least one below so the AI knows what to look for.</div>
      )}

      {/* How it works */}
      <div className={styles.infoBox}>
        <strong>How it works</strong>
        <ul>
          <li>Keyword rules run first — fast, under 10ms.</li>
          <li>If no keyword rule fires, the AI reviews the email against your policies below.</li>
          <li>Emails flagged with ≥70% confidence are blocked automatically.</li>
          <li>All AI decisions appear in your Scan Log with a reason.</li>
          <li>If AI is unavailable, emails pass through normally (fail-open).</li>
        </ul>
      </div>

      {/* Add policy */}
      <div className={styles.card}>
        <h2 className={styles.cardTitle}>Compliance Policies ({policies.length}/10)</h2>
        <form className={styles.addForm} onSubmit={handleAdd}>
          <textarea
            className={styles.textarea}
            value={text}
            onChange={e => setText(e.target.value)}
            placeholder="e.g. Do not guarantee specific investment returns or performance"
            rows={2}
            maxLength={500}
            disabled={policies.length >= 10}
          />
          <div className={styles.addRow}>
            <span className={styles.charCount}>{text.length}/500</span>
            <button
              type="submit"
              className={styles.addBtn}
              disabled={saving || !text.trim() || policies.length >= 10}
            >
              {saving ? 'Adding…' : '+ Add Policy'}
            </button>
          </div>
        </form>

        {policies.length === 0 ? (
          <p className={styles.empty}>No policies yet. Add one above to get started.</p>
        ) : (
          <ul className={styles.policyList}>
            {policies.map(p => (
              <li key={p.id} className={styles.policyItem}>
                <span className={styles.policyText}>{p.policy_text}</span>
                <button
                  className={styles.deleteBtn}
                  onClick={() => handleDelete(p.id)}
                  aria-label="Delete policy"
                >
                  ✕
                </button>
              </li>
            ))}
          </ul>
        )}
      </div>
    </div>
  );
}
