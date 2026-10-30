import { Component, type ErrorInfo, type ReactNode } from "react";
import { AlertTriangle } from "lucide-react";

/** One broken page must never blank the whole portal: show the error and a way out. */
export class ErrorBoundary extends Component<{ children: ReactNode; resetKey?: string }, { error: Error | null }> {
  state = { error: null as Error | null };

  static getDerivedStateFromError(error: Error) {
    return { error };
  }

  componentDidCatch(error: Error, info: ErrorInfo) {
    console.error("page error", error, info.componentStack);
  }

  componentDidUpdate(prev: { resetKey?: string }) {
    if (prev.resetKey !== this.props.resetKey && this.state.error) this.setState({ error: null });
  }

  render() {
    if (!this.state.error) return this.props.children;
    return (
      <div className="card error-box" role="alert">
        <div className="row" style={{ gap: 10, marginBottom: 8 }}>
          <AlertTriangle size={20} style={{ color: "var(--warn)" }} aria-hidden="true" />
          <h3 className="card-title">This page hit a problem</h3>
        </div>
        <p className="muted" style={{ marginBottom: 14 }}>{this.state.error.message}</p>
        <div className="row">
          <button className="btn primary" onClick={() => this.setState({ error: null })}>Try again</button>
          <a className="btn" href="/">Go to Home</a>
        </div>
      </div>
    );
  }
}
