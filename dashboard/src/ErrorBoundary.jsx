import { Component } from 'react';

// F-42: catch render-time exceptions in any widget so a single broken card
// doesn't blank the entire dashboard. Logs to console (no remote sink yet —
// we'll wire one up once we pick an APM).
export default class ErrorBoundary extends Component {
  constructor(props) {
    super(props);
    this.state = { error: null };
  }

  static getDerivedStateFromError(error) {
    return { error };
  }

  componentDidCatch(error, info) {
    // eslint-disable-next-line no-console
    console.error('[ErrorBoundary]', error, info?.componentStack);
  }

  reset = () => this.setState({ error: null });

  render() {
    if (!this.state.error) return this.props.children;
    return (
      <div style={{
        padding: 24,
        margin: 16,
        border: '1px solid #fecaca',
        background: '#fef2f2',
        borderRadius: 8,
        color: '#7f1d1d',
      }}>
        <h2 style={{ marginTop: 0 }}>Something went wrong</h2>
        <p>This part of the dashboard crashed. The rest of the app is still working.</p>
        <pre style={{
          background: '#fff',
          padding: 12,
          borderRadius: 4,
          overflow: 'auto',
          fontSize: 12,
        }}>{String(this.state.error?.message || this.state.error)}</pre>
        <button
          onClick={this.reset}
          style={{
            padding: '8px 16px',
            background: '#dc2626',
            color: '#fff',
            border: 'none',
            borderRadius: 4,
            cursor: 'pointer',
          }}
        >Try again</button>
      </div>
    );
  }
}
