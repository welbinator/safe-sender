import { useEffect, useState } from 'react';
import { getRules, createRule, updateRule, deleteRule } from '../api';
import styles from './RulesManager.module.css';

const BLANK = { name: '', pattern: '', match_type: 'string', scope: 'both', applies_to: '', is_exception: false };

export default function RulesManager() {
  const [rules, setRules] = useState([]);
  const [form, setForm] = useState(BLANK);
  const [editId, setEditId] = useState(null);
  const [error, setError] = useState('');
  const [saving, setSaving] = useState(false);

  const load = () => getRules().then(r => setRules(r.data)).catch(() => setError('Failed to load rules'));

  useEffect(() => { load(); }, []);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    setSaving(true);
    try {
      if (editId) {
        await updateRule(editId, form);
      } else {
        await createRule(form);
      }
      setForm(BLANK);
      setEditId(null);
      await load();
    } catch (err) {
      setError(err.response?.data?.detail || 'Failed to save rule');
    } finally {
      setSaving(false);
    }
  };

  const startEdit = (rule) => {
    setEditId(rule.id);
    setForm({
      name: rule.name || '',
      pattern: rule.pattern,
      match_type: rule.match_type,
      scope: rule.scope,
      applies_to: rule.applies_to_email || '',
      is_exception: rule.is_exception,
    });
  };

  const handleDelete = async (id) => {
    if (!confirm('Delete this rule?')) return;
    try {
      await deleteRule(id);
      await load();
    } catch {
      setError('Failed to delete rule');
    }
  };

  const cancel = () => { setForm(BLANK); setEditId(null); setError(''); };

  return (
    <div className={styles.container}>
      <h1 className={styles.title}>Rules</h1>

      <form className={styles.form} onSubmit={handleSubmit}>
        <h2 className={styles.formTitle}>{editId ? 'Edit Rule' : 'Add Rule'}</h2>
        {error && <div className={styles.error}>{error}</div>}
        <div className={styles.row}>
          <label>
            Rule Name <span className={styles.optional}>(optional)</span>
            <input
              value={form.name}
              onChange={e => setForm(f => ({ ...f, name: e.target.value }))}
              placeholder="e.g. Competitor Mentions"
            />
          </label>
          <label>
            Pattern
            <input
              required
              value={form.pattern}
              onChange={e => setForm(f => ({ ...f, pattern: e.target.value }))}
              placeholder="keyword or regex"
            />
          </label>
          <label>
            Match Type
            <select value={form.match_type} onChange={e => setForm(f => ({ ...f, match_type: e.target.value }))}>
              <option value="string">String (contains)</option>
              <option value="regex">Regex</option>
            </select>
          </label>
          <label>
            Scope
            <select value={form.scope} onChange={e => setForm(f => ({ ...f, scope: e.target.value }))}>
              <option value="both">Subject + Body</option>
              <option value="subject">Subject only</option>
              <option value="body">Body only</option>
            </select>
          </label>
        </div>
        <div className={styles.row}> 
          <label>
            Applies To (email, optional)
            <input
              value={form.applies_to}
              onChange={e => setForm(f => ({ ...f, applies_to: e.target.value }))}
              placeholder="user@yourdomain.com (blank = org-wide)"
            />
          </label>
          <label className={styles.checkboxLabel}>
            <input
              type="checkbox"
              checked={form.is_exception}
              onChange={e => setForm(f => ({ ...f, is_exception: e.target.checked }))}
            />
            Exception (allow, not block)
          </label>
        </div>
        <div className={styles.actions}>
          <button type="submit" disabled={saving}>{saving ? 'Saving…' : editId ? 'Update Rule' : 'Add Rule'}</button>
          {editId && <button type="button" onClick={cancel}>Cancel</button>}
        </div>
      </form>

      <table className={styles.table}>
        <thead>
          <tr>
            <th>Name</th>
            <th>Pattern</th>
            <th>Type</th>
            <th>Scope</th>
            <th>Applies To</th>
            <th>Exception</th>
            <th></th>
          </tr>
        </thead>
        <tbody>
          {rules.length === 0 && (
            <tr><td colSpan={7} className={styles.empty}>No rules yet. Add one above.</td></tr>
          )}
          {rules.map(rule => (
            <tr key={rule.id} className={rule.is_exception ? styles.exceptionRow : ''}>
              <td>{rule.name ? rule.name : <span className={styles.dim}>—</span>}</td>
              <td><code>{rule.pattern}</code></td>
              <td>{rule.match_type}</td>
              <td>{rule.scope}</td>
              <td>{rule.applies_to_email || <span className={styles.dim}>org-wide</span>}</td>
              <td>{rule.is_exception ? '✓' : ''}</td>
              <td className={styles.rowActions}>
                <button onClick={() => startEdit(rule)}>Edit</button>
                <button onClick={() => handleDelete(rule.id)} className={styles.deleteBtn}>Delete</button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
