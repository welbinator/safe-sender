import { useEffect, useState } from 'react';
import { getSmtpCredentials, rotateSmtpCredentials } from '../api';

export default function SmtpCredentials() {
  const [creds, setCreds] = useState(null);
  const [loading, setLoading] = useState(true);
  const [rotating, setRotating] = useState(false);
  const [newPassword, setNewPassword] = useState(null);
  const [copied, setCopied] = useState(false);
  const [error, setError] = useState(null);

  useEffect(() => {
    getSmtpCredentials()
      .then(r => setCreds(r.data))
      .catch(() => setError('Could not load SMTP credentials.'))
      .finally(() => setLoading(false));
  }, []);

  const handleRotate = async () => {
    if (!confirm('This will invalidate your current password. Your SMTP relay will stop working until you update it. Continue?')) return;
    setRotating(true);
    setNewPassword(null);
    setCopied(false);
    try {
      const r = await rotateSmtpCredentials();
      setCreds({ smtp_host: r.data.smtp_host, smtp_port: r.data.smtp_port, smtp_username: r.data.smtp_username });
      setNewPassword(r.data.smtp_password);
    } catch {
      setError('Failed to rotate credentials.');
    } finally {
      setRotating(false);
    }
  };

  const copy = (text) => {
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  if (loading) return <div className="widget"><p>Loading SMTP credentials…</p></div>;
  if (error) return <div className="widget"><p style={{ color: 'red' }}>{error}</p></div>;

  return (
    <div className="widget">
      <h3>SMTP Gateway Credentials</h3>
      <p style={{ color: '#666', fontSize: '14px', marginBottom: '16px' }}>
        Enter these into your Google Workspace SMTP relay configuration.
      </p>

      <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '14px' }}>
        <tbody>
          {[
            ['Host', creds.smtp_host],
            ['Port', creds.smtp_port],
            ['Security', 'STARTTLS'],
            ['Username', creds.smtp_username],
            ['Password', '••••••••••••  (rotate to generate a new one)'],
          ].map(([label, value]) => (
            <tr key={label} style={{ borderBottom: '1px solid #eee' }}>
              <td style={{ padding: '10px 8px', fontWeight: '600', color: '#555', width: '100px' }}>{label}</td>
              <td style={{ padding: '10px 8px', fontFamily: 'monospace' }}>{value}</td>
            </tr>
          ))}
        </tbody>
      </table>

      {newPassword && (
        <div style={{
          margin: '16px 0',
          padding: '14px',
          background: '#fffbea',
          border: '1px solid #f5c542',
          borderRadius: '6px',
        }}>
          <p style={{ margin: '0 0 8px', fontWeight: '600', color: '#7a5c00' }}>
            ⚠️ New password — save this now. It won't be shown again.
          </p>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <code style={{
              flex: 1,
              background: '#fff',
              border: '1px solid #ddd',
              borderRadius: '4px',
              padding: '8px 12px',
              fontSize: '15px',
              letterSpacing: '1px',
            }}>
              {newPassword}
            </code>
            <button
              onClick={() => copy(newPassword)}
              style={{
                padding: '8px 14px',
                background: copied ? '#22c55e' : '#1a1a1a',
                color: '#fff',
                border: 'none',
                borderRadius: '4px',
                cursor: 'pointer',
                fontSize: '13px',
                whiteSpace: 'nowrap',
              }}
            >
              {copied ? 'Copied!' : 'Copy'}
            </button>
          </div>
        </div>
      )}

      <button
        onClick={handleRotate}
        disabled={rotating}
        style={{
          marginTop: '12px',
          padding: '8px 16px',
          background: '#fff',
          border: '1px solid #d1d5db',
          borderRadius: '4px',
          cursor: rotating ? 'not-allowed' : 'pointer',
          fontSize: '13px',
          color: '#374151',
        }}
      >
        {rotating ? 'Rotating…' : 'Rotate password'}
      </button>
    </div>
  );
}
