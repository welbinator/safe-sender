import { useEffect, useState } from 'react';
import api from '../api';
import { extractErrorMessage } from '../errors';
import { SkeletonStats } from '../components/Skeleton';
import styles from './Stats.module.css';

/**
 * Overview card — server-side aggregation (F-39).
 *
 * Previously this widget pulled `/logs?date_from=YYYY-MM-DD&limit=500` and
 * counted in the browser, which (a) capped at 500 rows and silently
 * under-reported above that, (b) shipped every log row over the wire just
 * to compute three integers, and (c) misclassified today/yesterday for
 * users east of UTC.
 *
 * The backend now does all of this in SQL; we pass the client's timezone
 * offset (F-56) so "today" matches the user's wall clock.
 */
export default function Stats() {
  const [data, setData] = useState(null);
  const [error, setError] = useState(null);

  useEffect(() => {
    const tzOffset = new Date().getTimezoneOffset();
    api.get('/logs/stats/today', { params: { tz_offset_minutes: tzOffset } })
      .then(r => setData(r.data))
      .catch((err) => setError(extractErrorMessage(err, 'Failed to load stats')));
  }, []);

  if (error) return <div className={styles.error} role="alert">{error}</div>;
  if (!data) {
    return (
      <div className={styles.container}>
        <h1 className={styles.title}>Overview</h1>
        <SkeletonStats />
      </div>
    );
  }

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

      {data.top_rules && data.top_rules.length > 0 && (
        <div className={styles.topRules}>
          <h2>Top Triggered Rules</h2>
          <table className={styles.table}>
            <thead>
              <tr><th>Rule</th><th>Triggers</th></tr>
            </thead>
            <tbody>
              {data.top_rules.map(({ label, triggers }) => (
                <tr key={label}>
                  <td><code>{label}</code></td>
                  <td>{triggers}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
