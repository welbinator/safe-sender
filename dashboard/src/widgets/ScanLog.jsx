import { useEffect, useState, useCallback } from 'react';
import { getLogs } from '../api';
import styles from './ScanLog.module.css';

const PAGE_SIZE = 25;

export default function ScanLog() {
  const [logs, setLogs] = useState([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(0);
  const [filters, setFilters] = useState({ outcome: '', sender: '', date_from: '', date_to: '' });
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  const load = useCallback(() => {
    setLoading(true);
    const params = { page: page + 1, page_size: PAGE_SIZE };
    if (filters.outcome) params.outcome = filters.outcome;
    if (filters.sender) params.sender = filters.sender;
    if (filters.date_from) params.date_from = filters.date_from;
    if (filters.date_to) params.date_to = filters.date_to;

    getLogs(params)
      .then(r => {
        setLogs(r.data.results || []);
        setTotal(r.data.total || 0);
      })
      .catch(() => setError('Failed to load logs'))
      .finally(() => setLoading(false));
  }, [page, filters]);

  useEffect(() => { load(); }, [load]);

  const totalPages = Math.ceil(total / PAGE_SIZE);

  const applyFilter = (e) => {
    e.preventDefault();
    setPage(0);
    load();
  };

  const ruleLabel = (log) => {
    if (!log.matched_rule_id) return <span className={styles.dim}>—</span>;
    const name = log.matched_rule_name;
    const pattern = log.matched_rule_pattern;
    if (name) return <span title={pattern} className={styles.ruleName}>{name}</span>;
    return <code>{pattern}</code>;
  };

  return (
    <div className={styles.container}>
      <h1 className={styles.title}>Scan Logs</h1>

      <form className={styles.filters} onSubmit={applyFilter}>
        <select value={filters.outcome} onChange={e => setFilters(f => ({ ...f, outcome: e.target.value }))}>
          <option value="">All outcomes</option>
          <option value="allowed">Allowed</option>
          <option value="blocked">Blocked</option>
        </select>
        <input
          placeholder="Sender email"
          value={filters.sender}
          onChange={e => setFilters(f => ({ ...f, sender: e.target.value }))}
        />
        <input
          type="date"
          value={filters.date_from}
          onChange={e => setFilters(f => ({ ...f, date_from: e.target.value }))}
        />
        <input
          type="date"
          value={filters.date_to}
          onChange={e => setFilters(f => ({ ...f, date_to: e.target.value }))}
        />
        <button type="submit">Filter</button>
      </form>

      {error && <div className={styles.error}>{error}</div>}

      <div className={styles.tableWrap}>
        <table className={styles.table}>
          <thead>
            <tr>
              <th>Time</th>
              <th>From</th>
              <th>To</th>
              <th>Subject</th>
              <th>Outcome</th>
              <th>Rule Triggered</th>
            </tr>
          </thead>
          <tbody>
            {loading && (
              <tr><td colSpan={6} className={styles.loading}>Loading…</td></tr>
            )}
            {!loading && logs.length === 0 && (
              <tr><td colSpan={6} className={styles.empty}>No logs found.</td></tr>
            )}
            {!loading && logs.map((log, i) => (
              <tr key={i}>
                <td className={styles.time}>{new Date(log.created_at).toLocaleString()}</td>
                <td className={styles.email}>{log.sender}</td>
                <td className={styles.email}>{log.recipient}</td>
                <td className={styles.subject}>{log.subject || <span className={styles.dim}>—</span>}</td>
                <td>
                  <span className={log.outcome === 'blocked' ? styles.blocked : styles.allowed}>
                    {log.outcome === 'blocked' ? '🚫 blocked' : '✓ delivered'}
                  </span>
                </td>
                <td className={styles.rule}>{ruleLabel(log)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {totalPages > 1 && (
        <div className={styles.pagination}>
          <button disabled={page === 0} onClick={() => setPage(p => p - 1)}>← Prev</button>
          <span>Page {page + 1} of {totalPages}</span>
          <button disabled={page >= totalPages - 1} onClick={() => setPage(p => p + 1)}>Next →</button>
        </div>
      )}
    </div>
  );
}