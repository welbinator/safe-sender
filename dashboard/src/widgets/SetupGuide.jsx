/**
 * SetupGuide — Sprint 5 onboarding wizard.
 *
 * Four steps:
 *  1. Verify your domain(s) (multi-domain manager)
 *  2. Configure SMTP gateway in Google Workspace
 *  3. Add your first rule
 *  4. Test your connection (true end-to-end SMTP test)
 */

import { useState, useEffect } from 'react';
import { getMe, getRules, getDomains, addDomain, domainVerifyInit, domainVerifyCheck, deleteDomain, testConnection, getTestConnectionStatus } from '../api';

// ---------------------------------------------------------------------------
// Tiny shared UI helpers
// ---------------------------------------------------------------------------

const Card = ({ children, style = {} }) => (
  <div style={{
    background: '#1a1a2e',
    border: '1px solid #2a2a4a',
    borderRadius: 12,
    padding: '24px 28px',
    marginBottom: 24,
    ...style,
  }}>
    {children}
  </div>
);

const StepHeader = ({ num, title, done }) => (
  <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 16 }}>
    <div style={{
      width: 32, height: 32, borderRadius: '50%',
      background: done ? '#22c55e' : '#6c63ff',
      display: 'flex', alignItems: 'center', justifyContent: 'center',
      fontSize: 14, fontWeight: 700, color: '#fff', flexShrink: 0,
    }}>
      {done ? '✓' : num}
    </div>
    <h3 style={{ margin: 0, color: done ? '#22c55e' : '#e0e0ff', fontSize: 17 }}>{title}</h3>
  </div>
);

const Btn = ({ onClick, disabled, loading, children, variant = 'primary' }) => {
  const base = {
    padding: '9px 20px', borderRadius: 8, border: 'none',
    fontWeight: 600, fontSize: 14, cursor: disabled ? 'not-allowed' : 'pointer',
    transition: 'opacity 0.15s',
    opacity: disabled ? 0.5 : 1,
  };
  const styles = {
    primary: { background: '#6c63ff', color: '#fff' },
    success: { background: '#22c55e', color: '#fff' },
    ghost:   { background: 'transparent', color: '#6c63ff', border: '1px solid #6c63ff' },
  };
  return (
    <button style={{ ...base, ...styles[variant] }} onClick={onClick} disabled={disabled}>
      {loading ? '⏳ Working…' : children}
    </button>
  );
};

const Code = ({ children }) => (
  <code style={{
    background: '#0d0d1a', color: '#a0f0a0', padding: '3px 8px',
    borderRadius: 5, fontFamily: 'monospace', fontSize: 13,
    userSelect: 'all',
  }}>
    {children}
  </code>
);

const Alert = ({ type, children, style = {} }) => {
  const colors = { info: '#3b82f6', success: '#22c55e', warn: '#f59e0b', error: '#ef4444' };
  return (
    <div style={{
      background: colors[type] + '20',
      border: `1px solid ${colors[type]}40`,
      borderLeft: `4px solid ${colors[type]}`,
      borderRadius: 8, padding: '10px 14px',
      color: '#e0e0ff', fontSize: 14, marginTop: 12,
      ...style,
    }}>
      {children}
    </div>
  );
};

// ---------------------------------------------------------------------------
// Step 1 — Multi-domain manager
// ---------------------------------------------------------------------------

const DomainRow = ({ entry, onVerify, onRemove, canRemove }) => {
  const [expanded, setExpanded] = useState(false);
  const [tokenInfo, setTokenInfo] = useState(null);
  const [initLoading, setInitLoading] = useState(false);
  const [checkLoading, setCheckLoading] = useState(false);
  const [msg, setMsg] = useState(null);

  const handleInit = async () => {
    setInitLoading(true);
    setMsg(null);
    try {
      const res = await domainVerifyInit(entry.domain);
      setTokenInfo(res.data);
      setExpanded(true);
    } catch (e) {
      setMsg({ type: 'error', text: 'Failed to generate token. Try again.' });
    } finally {
      setInitLoading(false);
    }
  };

  const handleCheck = async () => {
    setCheckLoading(true);
    setMsg(null);
    try {
      const res = await domainVerifyCheck(entry.domain);
      if (res.data.verified) {
        onVerify(entry.domain);
        setMsg({ type: 'success', text: '✅ Domain verified!' });
        setExpanded(false);
      } else {
        setMsg({ type: 'warn', text: res.data.message });
      }
    } catch (e) {
      setMsg({ type: 'error', text: 'Check failed. Try again.' });
    } finally {
      setCheckLoading(false);
    }
  };

  return (
    <div style={{
      border: '1px solid #2a2a4a',
      borderRadius: 8,
      padding: '12px 16px',
      marginBottom: 10,
      background: '#12122a',
    }}>
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 8, flexWrap: "wrap" }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <span style={{
            width: 10, height: 10, borderRadius: '50%', flexShrink: 0,
            background: entry.verified ? '#22c55e' : '#f59e0b',
            display: 'inline-block',
          }} />
          <span style={{ color: '#e0e0ff', fontSize: 14, fontFamily: 'monospace' }}>{entry.domain}</span>
          <span style={{ fontSize: 12, color: entry.verified ? '#22c55e' : '#f59e0b' }}>
            {entry.verified ? 'Verified' : 'Pending'}
          </span>
        </div>
        <div style={{ display: "flex", gap: 8, flexShrink: 0, marginLeft: "auto" }}>
          {!entry.verified && (
            <Btn onClick={handleInit} loading={initLoading} disabled={initLoading} variant="ghost">
              {expanded ? 'Refresh token' : 'Verify'}
            </Btn>
          )}
          {canRemove && (
            <Btn onClick={() => onRemove(entry.domain)} variant="ghost">
              Remove
            </Btn>
          )}
        </div>
      </div>

      {expanded && tokenInfo && (
        <div style={{ marginTop: 14, paddingTop: 14, borderTop: '1px solid #2a2a4a' }}>
          <p style={{ color: '#a0a0c0', fontSize: 13, margin: '0 0 10px 0' }}>
            Add this TXT record to your DNS, then click verify:
          </p>
          <table style={{ fontSize: 13, borderCollapse: 'collapse', width: '100%' }}>
            <tbody>
              <tr>
                <td style={{ color: '#6c63ff', paddingRight: 16, paddingBottom: 6, width: 60, verticalAlign: 'top' }}>Name</td>
                <td style={{ wordBreak: 'break-all' }}><Code>_sendersafety.{entry.domain}</Code></td>
              </tr>
              <tr>
                <td style={{ color: '#6c63ff', paddingBottom: 6 }}>Type</td>
                <td><Code>TXT</Code></td>
              </tr>
              <tr>
                <td style={{ color: '#6c63ff', verticalAlign: 'top' }}>Value</td>
                <td style={{ wordBreak: 'break-all' }}><Code>{tokenInfo.txt_value}</Code></td>
              </tr>
            </tbody>
          </table>
          <div style={{ marginTop: 12 }}>
            <Btn onClick={handleCheck} loading={checkLoading} disabled={checkLoading}>
              I've added it — verify now
            </Btn>
          </div>
          {msg && <Alert type={msg.type} style={{ marginTop: 10 }}>{msg.text}</Alert>}
        </div>
      )}

      {!expanded && msg && <Alert type={msg.type} style={{ marginTop: 10 }}>{msg.text}</Alert>}
    </div>
  );
};

const AddDomainInput = ({ value, onChange, onAdd, loading, error }) => (
  <div>
    <div style={{ display: 'flex', gap: 8 }}>
      <input
        type="text"
        placeholder="example.com"
        value={value}
        onChange={e => onChange(e.target.value)}
        onKeyDown={e => e.key === 'Enter' && onAdd()}
        style={{
          flex: 1, background: '#0d0d1a', border: '1px solid #2a2a4a',
          borderRadius: 8, padding: '8px 12px', color: '#e0e0ff',
          fontSize: 14, outline: 'none',
        }}
      />
      <Btn onClick={onAdd} loading={loading} disabled={loading || !value.trim()}>
        Add
      </Btn>
    </div>
    {error && <Alert type="error" style={{ marginTop: 8 }}>{error}</Alert>}
  </div>
);

const StepVerifyDomain = ({ domains, onDomainsChange }) => {
  const [addInput, setAddInput] = useState('');
  const [addLoading, setAddLoading] = useState(false);
  const [addError, setAddError] = useState(null);

  const hasVerified = domains.some(d => d.verified);

  const handleAdd = async () => {
    const normalized = addInput.trim().toLowerCase().replace(/^www\./, '');
    if (!normalized) return;
    setAddLoading(true);
    setAddError(null);
    try {
      const res = await addDomain(normalized);
      onDomainsChange([...domains, res.data]);
      setAddInput('');
    } catch (e) {
      const msg = e.response?.data?.detail;
      if (e.response?.status === 409) {
        setAddError('This domain has already been verified by another account. If you believe this is an error, contact support.');
      } else {
        setAddError(msg || 'Failed to add domain. Try again.');
      }
    } finally {
      setAddLoading(false);
    }
  };

  const handleVerify = (domain) => {
    onDomainsChange(domains.map(d => d.domain === domain ? { ...d, verified: true } : d));
  };

  const handleRemove = async (domain) => {
    try {
      await deleteDomain(domain);
      onDomainsChange(domains.filter(d => d.domain !== domain));
    } catch (e) {
      const msg = e.response?.data?.detail || 'Could not remove domain.';
      alert(msg);
    }
  };

  const verifiedCount = domains.filter(d => d.verified).length;

  if (hasVerified && domains.length === 1) {
    return (
      <Card>
        <StepHeader num={1} title="Verify your domain(s)" done />
        <Alert type="success">✅ <strong>{domains[0].domain}</strong> is verified.</Alert>
        <div style={{ marginTop: 14 }}>
          <p style={{ color: '#7070a0', fontSize: 13, margin: '0 0 8px 0' }}>Need to add another domain?</p>
          <AddDomainInput
            value={addInput} onChange={setAddInput}
            onAdd={handleAdd} loading={addLoading} error={addError}
          />
        </div>
      </Card>
    );
  }

  return (
    <Card>
      <StepHeader num={1} title="Verify your domain(s)" done={hasVerified} />
      <p style={{ color: '#a0a0c0', fontSize: 14, marginTop: 0, marginBottom: 16 }}>
        Verify every domain your organisation sends email from. Emails arriving from unverified domains will be rejected.
      </p>

      {domains.length === 0 && (
        <Alert type="warn" style={{ marginBottom: 14 }}>
          No domains yet. Add your first domain below.
        </Alert>
      )}

      {domains.map(entry => (
        <DomainRow
          key={entry.domain}
          entry={entry}
          onVerify={handleVerify}
          onRemove={handleRemove}
          canRemove={!(entry.verified && verifiedCount === 1)}
        />
      ))}

      <div style={{ marginTop: 16 }}>
        <p style={{ color: '#7070a0', fontSize: 13, margin: '0 0 8px 0' }}>
          {domains.length === 0 ? 'Enter your domain:' : 'Add another domain:'}
        </p>
        <AddDomainInput
          value={addInput} onChange={setAddInput}
          onAdd={handleAdd} loading={addLoading} error={addError}
        />
      </div>
    </Card>
  );
};

// ---------------------------------------------------------------------------
// Step 2 — SMTP gateway config (Google Workspace or Microsoft 365)
// ---------------------------------------------------------------------------

const StepSmtpConfig = ({ domain, authProvider }) => {
  const [platform, setPlatform] = useState(authProvider === 'microsoft' ? 'microsoft' : 'google');

  return (
    <Card>
      <StepHeader num={2} title="Configure your SMTP gateway" done={false} />
      <p style={{ color: '#a0a0c0', fontSize: 14, marginTop: 0 }}>
        Route all outbound email through Sender Safety.
      </p>

      {platform === 'google' ? (
        <>
          <ol style={{ color: '#c0c0e0', fontSize: 14, lineHeight: 1.8, paddingLeft: 20, margin: 0 }}>
            <li>
              Open <a href="https://admin.google.com" target="_blank" rel="noreferrer"
                style={{ color: '#6c63ff' }}>Google Workspace Admin</a>
            </li>
            <li>Go to <strong>Apps → Google Workspace → Gmail → Routing</strong></li>
            <li>Under <strong>Outbound gateway</strong>, click <em>Configure</em></li>
            <li>Set the outbound gateway to: <Code>smtp.sendersafety.com</Code></li>
            <li>Save and apply to your entire organisation</li>
          </ol>
          <Alert type="info" style={{ marginTop: 16 }}>
            💡 Changes in Google Workspace Admin can take up to an hour to propagate.
          </Alert>
          <div style={{ marginTop: 14 }}>
            <button
              onClick={() => setPlatform('microsoft')}
              style={{ background: 'none', border: 'none', color: '#6c63ff', cursor: 'pointer', fontSize: 13, padding: 0 }}
            >
              Using Microsoft 365? Switch →
            </button>
          </div>
        </>
      ) : (
        <>
          <ol style={{ color: '#c0c0e0', fontSize: 14, lineHeight: 1.8, paddingLeft: 20, margin: 0 }}>
            <li>
              Go to <a href="https://admin.exchange.microsoft.com" target="_blank" rel="noreferrer"
                style={{ color: '#6c63ff' }}>Exchange Admin Center</a>
            </li>
            <li>Go to <strong>Mail flow → Connectors → + Add a connector</strong></li>
            <li>Connection from: select <strong>Office 365</strong></li>
            <li>Connection to: select <strong>Partner organization</strong></li>
            <li>Name: <em>Sender Safety outbound filter</em></li>
            <li>
              Use of connector: select <em>"Only when email messages are sent to these domains"</em>,
              type <Code>*</Code> in the box and click <strong>+</strong> — this routes all outbound email through the connector
            </li>
            <li>
              Routing: select <em>"Route email through these smart hosts"</em>, then enter <Code>smtp.sendersafety.com</Code> and click <strong>+</strong>
            </li>
            <li>
              Security: <strong>Always use TLS</strong> — when asked how to identify the partner
              organization, choose <em>"By verifying that the sender domain matches"</em> and
              enter <Code>sendersafety.com</Code>
            </li>
            <li>
              Security restrictions: keep <em>"Reject email messages if they aren't sent over TLS"</em> checked,
              also check <em>"And require that the subject name on the certificate matches"</em> and
              enter <Code>smtp.sendersafety.com</Code>. Leave the IP address range box unchecked.
            </li>
            <li>Save the connector</li>
          </ol>
          <Alert type="info" style={{ marginTop: 16 }}>
            💡 Connector changes in Exchange Admin Center typically propagate within 30 minutes.
          </Alert>
          <div style={{ marginTop: 14 }}>
            <button
              onClick={() => setPlatform('google')}
              style={{ background: 'none', border: 'none', color: '#6c63ff', cursor: 'pointer', fontSize: 13, padding: 0 }}
            >
              Using Google Workspace? Switch →
            </button>
          </div>
        </>
      )}
    </Card>
  );
};

// ---------------------------------------------------------------------------
// Step 3 — First rule reminder (links to Rules page)
// ---------------------------------------------------------------------------

const StepFirstRule = ({ hasRules }) => (
  <Card>
    <StepHeader num={3} title="Add your first rule" done={hasRules} />
    {hasRules ? (
      <Alert type="success">✅ You have at least one rule configured.</Alert>
    ) : (
      <>
        <p style={{ color: '#a0a0c0', fontSize: 14, marginTop: 0 }}>
          Rules define which words or phrases should be flagged or blocked in outbound emails.
          Even one rule is enough to get started.
        </p>
        <a href="/rules" style={{ display: 'inline-block', marginTop: 4 }}>
          <Btn variant="ghost">Go to Rules →</Btn>
        </a>
      </>
    )}
  </Card>
);

// ---------------------------------------------------------------------------
// Step 4 — Test connection
// ---------------------------------------------------------------------------

const StepTestConnection = ({ domain, domainVerified }) => {
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);

  const handleTest = async () => {
    setLoading(true);
    setResult(null);
    try {
      const start = await testConnection();
      const testId = start.data.test_id;
      // Poll up to ~30s (15 × 2s). Matches backend SMTP/poll worst case
      // (test_poll_deadline=10s + slack for SMTP TLS+send).
      let finalRes = null;
      for (let i = 0; i < 15; i++) {
        await new Promise((r) => setTimeout(r, 2000));
        try {
          const poll = await getTestConnectionStatus(testId);
          if (poll.data.status === 'done') {
            finalRes = { success: poll.data.success, message: poll.data.message };
            break;
          }
        } catch (_) {
          // Transient — keep polling. If the test_id 404s permanently we'll
          // fall out of the loop and show the timeout message below.
        }
      }
      setResult(
        finalRes ?? {
          success: false,
          message: 'Test is still running — try again in a moment.',
        }
      );
    } catch (e) {
      setResult({ success: false, message: 'Request failed. Is the backend reachable?' });
    } finally {
      setLoading(false);
    }
  };

  return (
    <Card>
      <StepHeader num={4} title="Test your connection" done={result?.success} />
      <p style={{ color: '#a0a0c0', fontSize: 14, marginTop: 0 }}>
        Send a real test email through the Sender Safety gateway and confirm it shows up in your scan logs.
      </p>
      {!domainVerified && (
        <Alert type="warn">⚠️ Verify your domain first (Step 1) before running a connection test.</Alert>
      )}
      <Btn
        onClick={handleTest}
        loading={loading}
        disabled={loading || !domainVerified}
        variant={result?.success ? 'success' : 'primary'}
      >
        {result?.success ? '✓ Test passed!' : 'Send test email'}
      </Btn>
      {result && (
        <Alert type={result.success ? 'success' : 'error'} style={{ marginTop: 12 }}>
          {result.message}
        </Alert>
      )}
    </Card>
  );
};

// ---------------------------------------------------------------------------
// Main component
// ---------------------------------------------------------------------------

export default function SetupGuide() {
  const [customer, setCustomer] = useState(null);
  const [domains, setDomains] = useState([]);
  const [domainVerified, setDomainVerified] = useState(false);
  const [hasRules, setHasRules] = useState(false);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const load = async () => {
      try {
        const [meRes, rulesRes, domainsRes] = await Promise.all([getMe(), getRules(), getDomains()]);
        setCustomer(meRes.data);
        setDomains(domainsRes.data || []);
        setDomainVerified((domainsRes.data || []).some(d => d.verified));
        setHasRules((rulesRes.data || []).length > 0);
      } catch (_) {}
      setLoading(false);
    };
    load();
  }, []);

  if (loading) {
    return (
      <div style={{ padding: 40, color: '#6c63ff', fontSize: 16 }}>Loading setup guide…</div>
    );
  }

  const domain = customer?.domain || '(your domain)';
  const allDone = domainVerified;

  return (
    <div style={{ maxWidth: 680, margin: '0 auto', padding: '32px 16px' }}>
      <div style={{ marginBottom: 28 }}>
        <h2 style={{ color: '#e0e0ff', margin: '0 0 6px 0', fontSize: 22 }}>
          🚀 Get started with Sender Safety
        </h2>
        <p style={{ color: '#7070a0', margin: 0, fontSize: 14 }}>
          Four steps to protect every email leaving your organisation.
        </p>
      </div>

      {allDone && (
        <Alert type="success" style={{ marginBottom: 24 }}>
          🎉 You're all set! Sender Safety is actively filtering outbound email.
        </Alert>
      )}

      <StepVerifyDomain
        domains={domains}
        onDomainsChange={(updated) => {
          setDomains(updated);
          setDomainVerified(updated.some(d => d.verified));
        }}
      />

      <StepSmtpConfig domain={domain} authProvider={customer?.auth_provider || 'google'} />

      <StepFirstRule hasRules={hasRules} />

      <StepTestConnection domain={domain} domainVerified={domainVerified} />
    </div>
  );
}
