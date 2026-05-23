/**
 * SetupGuide — Sprint 5 onboarding wizard.
 *
 * Four steps:
 *  1. Verify your domain (DNS TXT record)
 *  2. Configure SMTP gateway in Google Workspace
 *  3. Add your first rule
 *  4. Test your connection (true end-to-end SMTP test)
 */

import { useState, useEffect } from 'react';
import { getMe, getRules, verifyDomainInit, verifyDomainCheck, testConnection, getTestConnectionStatus } from '../api';

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

const Alert = ({ type, children }) => {
  const colors = { info: '#3b82f6', success: '#22c55e', warn: '#f59e0b', error: '#ef4444' };
  return (
    <div style={{
      background: colors[type] + '20',
      border: `1px solid ${colors[type]}40`,
      borderLeft: `4px solid ${colors[type]}`,
      borderRadius: 8, padding: '10px 14px',
      color: '#e0e0ff', fontSize: 14, marginTop: 12,
    }}>
      {children}
    </div>
  );
};

// ---------------------------------------------------------------------------
// Step 1 — Domain verification
// ---------------------------------------------------------------------------

const StepVerifyDomain = ({ domain, alreadyVerified, onVerified }) => {
  const [token, setToken] = useState(null);
  const [initLoading, setInitLoading] = useState(false);
  const [checkLoading, setCheckLoading] = useState(false);
  const [msg, setMsg] = useState(null);
  const [verified, setVerified] = useState(alreadyVerified);

  const handleInit = async () => {
    setInitLoading(true);
    setMsg(null);
    try {
      const res = await verifyDomainInit();
      setToken(res.data.txt_value);
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
      const res = await verifyDomainCheck();
      if (res.data.verified) {
        setVerified(true);
        onVerified();
        setMsg({ type: 'success', text: res.data.message });
      } else {
        setMsg({ type: 'warn', text: res.data.message });
      }
    } catch (e) {
      setMsg({ type: 'error', text: 'Check failed. Try again.' });
    } finally {
      setCheckLoading(false);
    }
  };

  if (verified) {
    return (
      <Card>
        <StepHeader num={1} title="Verify your domain" done />
        <Alert type="success">✅ <strong>{domain}</strong> is verified.</Alert>
      </Card>
    );
  }

  return (
    <Card>
      <StepHeader num={1} title="Verify your domain" done={false} />
      <p style={{ color: '#a0a0c0', fontSize: 14, marginTop: 0 }}>
        Prove you own <strong style={{ color: '#e0e0ff' }}>{domain}</strong> by adding a DNS TXT record.
      </p>

      {!token && (
        <Btn onClick={handleInit} loading={initLoading} disabled={initLoading}>
          Generate verification token
        </Btn>
      )}

      {token && (
        <div style={{ marginTop: 12 }}>
          <p style={{ color: '#a0a0c0', fontSize: 14, margin: '0 0 8px 0' }}>
            Add this TXT record to your DNS:
          </p>
          <table style={{ fontSize: 13, borderCollapse: 'collapse', width: '100%' }}>
            <tbody>
              <tr>
                <td style={{ color: '#6c63ff', paddingRight: 16, paddingBottom: 6, width: 80 }}>Name</td>
                <td><Code>_sendersafety.{domain}</Code></td>
              </tr>
              <tr>
                <td style={{ color: '#6c63ff', paddingBottom: 6 }}>Type</td>
                <td><Code>TXT</Code></td>
              </tr>
              <tr>
                <td style={{ color: '#6c63ff' }}>Value</td>
                <td><Code>{token}</Code></td>
              </tr>
            </tbody>
          </table>
          <p style={{ color: '#a0a0c0', fontSize: 13, margin: '12px 0' }}>
            DNS changes can take a few minutes to a few hours to propagate. Once you've added the record, click below.
          </p>
          <Btn onClick={handleCheck} loading={checkLoading} disabled={checkLoading}>
            I've added it — verify now
          </Btn>
        </div>
      )}

      {msg && <Alert type={msg.type}>{msg.text}</Alert>}
    </Card>
  );
};

// ---------------------------------------------------------------------------
// Step 2 — SMTP gateway config
// ---------------------------------------------------------------------------

const StepSmtpConfig = ({ domain }) => (
  <Card>
    <StepHeader num={2} title="Configure your SMTP gateway" done={false} />
    <p style={{ color: '#a0a0c0', fontSize: 14, marginTop: 0 }}>
      Tell Google Workspace to route all outbound email through Sender Safety.
    </p>
    <ol style={{ color: '#c0c0e0', fontSize: 14, lineHeight: 1.8, paddingLeft: 20, margin: 0 }}>
      <li>
        Open <a href="https://admin.google.com" target="_blank" rel="noreferrer"
          style={{ color: '#6c63ff' }}>Google Workspace Admin</a>
      </li>
      <li>Go to <strong>Apps → Google Workspace → Gmail → Routing</strong></li>
      <li>Under <strong>Outbound gateway</strong>, click <em>Configure</em></li>
      <li>
        Set the outbound gateway to: <Code>smtp.sendersafety.com</Code>
      </li>

      <li>Save and apply to your entire organisation</li>
    </ol>
    <Alert type="info" style={{ marginTop: 16 }}>
      💡 Changes in Google Workspace Admin can take up to an hour to propagate across your org.
    </Alert>
  </Card>
);

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
  const [domainVerified, setDomainVerified] = useState(false);
  const [hasRules, setHasRules] = useState(false);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const load = async () => {
      try {
        const [meRes, rulesRes] = await Promise.all([getMe(), getRules()]);
        setCustomer(meRes.data);
        setDomainVerified(meRes.data.domain_verified);
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
          Four steps to protect every email leaving <strong style={{ color: '#a0a0d0' }}>{domain}</strong>.
        </p>
      </div>

      {allDone && (
        <Alert type="success" style={{ marginBottom: 24 }}>
          🎉 You're all set! Sender Safety is actively filtering outbound email for <strong>{domain}</strong>.
        </Alert>
      )}

      <StepVerifyDomain
        domain={domain}
        alreadyVerified={domainVerified}
        onVerified={() => setDomainVerified(true)}
      />

      <StepSmtpConfig domain={domain} />

      <StepFirstRule hasRules={hasRules} />

      <StepTestConnection domain={domain} domainVerified={domainVerified} />
    </div>
  );
}
