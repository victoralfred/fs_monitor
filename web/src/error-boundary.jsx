// Preact error boundary. Catches render-time exceptions so a single bad
// component doesn't break the whole app.

import { Component } from 'preact';

export class ErrorBoundary extends Component {
  constructor(props) {
    super(props);
    this.state = { err: null };
  }

  static getDerivedStateFromError(err) {
    return { err };
  }

  componentDidCatch(err, info) {
    // eslint-disable-next-line no-console
    console.error('UI render error', err, info);
  }

  render() {
    if (this.state.err) {
      return (
        <div
          style={{
            padding: 24,
            color: 'var(--text)',
            background: 'var(--bg)',
            fontFamily: 'ui-sans-serif, system-ui, sans-serif',
          }}
        >
          <h2 style={{ marginTop: 0 }}>Something broke.</h2>
          <p style={{ color: 'var(--muted)' }}>
            A component threw an exception. The rest of the app may still be usable after a reload.
            Details:
          </p>
          <pre
            style={{
              background: 'var(--panel)',
              border: '1px solid var(--border)',
              padding: 12,
              overflow: 'auto',
              fontSize: 12,
            }}
          >
            {String(this.state.err?.stack || this.state.err)}
          </pre>
          <button class="theme-btn" onClick={() => this.setState({ err: null })}>
            try again
          </button>
        </div>
      );
    }
    return this.props.children;
  }
}
