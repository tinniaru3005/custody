import type { ReactNode } from "react";
import { ApiError } from "../api/client";
import type { ActionStatus, Verdict } from "../api/types";
import { STATUS_LABEL, VERDICT_LABEL, verdictClass } from "../lib/format";

export function VerdictBadge({
  verdict,
  large,
}: {
  verdict?: Verdict | string | null;
  large?: boolean;
}) {
  if (!verdict) return <span className="badge none">not checked</span>;
  const cls = verdictClass(verdict);
  const icon = cls === "allow" ? "✓" : cls === "block" ? "⛔" : "✋";
  return (
    <span className={`badge ${cls}${large ? " large" : ""}`} data-testid="verdict-badge">
      <span aria-hidden>{icon}</span> {VERDICT_LABEL[verdict as Verdict] ?? verdict}
    </span>
  );
}

export function StatusBadge({ status }: { status?: string | null }) {
  if (!status) return null;
  return (
    <span className={`status status-${status}`}>
      {STATUS_LABEL[status as ActionStatus] ?? status}
    </span>
  );
}

const FLAG_TEXT: Record<string, string> = {
  untrusted: "untrusted",
  trusted: "trusted",
  secret: "secret",
  tainted: "tainted",
  quarantined: "quarantined",
  blocked: "blocked",
  endorsed: "endorsed",
  external: "external",
  internal: "internal",
  warden: "warden",
};

export function Flag({ flag }: { flag: string }) {
  return <span className={`flag flag-${flag}`}>{FLAG_TEXT[flag] ?? flag}</span>;
}

export function Panel({
  title,
  actions,
  children,
  className,
  subtitle,
}: {
  title?: ReactNode;
  subtitle?: ReactNode;
  actions?: ReactNode;
  children: ReactNode;
  className?: string;
}) {
  return (
    <section className={`panel ${className ?? ""}`}>
      {(title || actions) && (
        <header className="panel-head">
          <div>
            {title && <h2>{title}</h2>}
            {subtitle && <p className="muted small">{subtitle}</p>}
          </div>
          {actions && <div className="panel-actions">{actions}</div>}
        </header>
      )}
      {children}
    </section>
  );
}

export function Stat({
  label,
  value,
  tone,
  hint,
  testId,
}: {
  label: string;
  value: ReactNode;
  tone?: "allow" | "block" | "approval" | "quarantine" | "secret";
  hint?: ReactNode;
  testId?: string;
}) {
  return (
    <div className={`stat ${tone ? `stat-${tone}` : ""}`} data-testid={testId}>
      <div className="stat-label">{label}</div>
      <div className="stat-value">{value}</div>
      {hint && <div className="stat-hint">{hint}</div>}
    </div>
  );
}

export function Loading({ label = "Loading…" }: { label?: string }) {
  return (
    <div className="loading" role="status">
      <span className="spinner" aria-hidden /> {label}
    </div>
  );
}

export function ErrorState({ error, onRetry }: { error: unknown; onRetry?: () => void }) {
  const msg = error instanceof Error ? error.message : String(error);
  const offline = error instanceof ApiError && error.status === 0;
  return (
    <div className="error-state" role="alert">
      <strong>{offline ? "Backend unreachable" : "Something went wrong"}</strong>
      <p>{msg}</p>
      {offline && (
        <p className="muted small">
          Start it with <code>uvicorn custody.api.app:app --port 8000</code>.
        </p>
      )}
      {onRetry && (
        <button className="btn" onClick={onRetry}>
          Retry
        </button>
      )}
    </div>
  );
}

export function Empty({ title, children }: { title: string; children?: ReactNode }) {
  return (
    <div className="empty">
      <strong>{title}</strong>
      {children && <div className="muted">{children}</div>}
    </div>
  );
}

/** Text that came from an untrusted source: rendered as inert data, never as markup. */
export function UntrustedText({
  text,
  label = "attacker-controlled content, shown as data",
}: {
  text: string;
  label?: string;
}) {
  return (
    <figure className="untrusted-text">
      <figcaption>⚠ {label}</figcaption>
      <pre>{text}</pre>
    </figure>
  );
}
