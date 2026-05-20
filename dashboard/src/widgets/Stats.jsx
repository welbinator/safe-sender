
import { useEffect, useState } from 'react';
import api from '../api';
import styles from './Stats.module.css';

export default function Stats() {
  const [data, setData] = useState(null);
  const [error, setError] = useState(null);

  useEffect(() => {
    // Derive stats from logs endpoint (today's date range)
    const today = new Date().toISOString().split('T')[0];
    api.get('/logs', { params: { date_from: today, limit: 500 } })
      .then(r => {
        const logs = r.data.results || [];
        const scanned = logs.length;
        const blocked = logs.filter(l => l.outcome === 'blocked').length;
        const allowed = logs.filter(l => l.outcome === 'allowed').length;

        // Top triggered rules
        const ruleCounts = {};
        logs.filter(l => l.matched_rule).forEach(l => {
          ruleCounts[l.matched_rule] = (ruleCounts[l.matched_rule] || 0) + 1;
        });
        const topRules = Object.entries(ruleCounts)
          .sort((a, b) => b[1] - a[1])
          .slice(0, 5);

        setData({ scanned, blocked, allowed, topRules });
      })
      .catch(() => setError('Failed to load stats'));
  }, []);

  if (error) return <div className={styles.error}>{error}</div>;
  if (!data) return <div className={styles.loading}>Loading…</div>;

  return (
    <div className={styles.container}>
      <h1 className={styles.title}>Overview</h1>
      <div className={styles.cards}>
        <div className={styles.card}>
          <div className={styles.cardLabel}>Emails Scanned Today</div>
          <div className={styles.cardValue}>{data.scanned}</div>
        </div>
        <div className={`${styles.card} ${styles.blocked}`}>
          <div className={styles.cardLabel}>Blocked Today</div>
          <div className={styles.cardValue}>{data.blocked}</div>
        </div>
        <div className={`${styles.card} ${styles.allowed}`}>
          <div className={styles.cardLabel}>Allowed Today</div>
          <div className={styles.cardValue}>{data.allowed}</div>
        </div>
      </div>

      {data.topRules.length > 0 && (
        <div className={styles.topRules}>
          <h2>Top Triggered Rules</h2>
          <table className={styles.table}>
            <thead>
              <tr><th>Rule Pattern</th><th>Triggers</th></tr>
            </thead>
            <tbody>
              {data.topRules.map(([rule, count]) => (
                <tr key={rule}>
                  <td><code>{rule}</code></td>
                  <td>{count}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
