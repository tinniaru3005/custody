import { useState, type ReactNode } from "react";
import { NavLink } from "react-router-dom";
import { useApprovals, useHealth, useReset } from "../api/hooks";
import { TENANT } from "../api/client";

const NAV = [
  { to: "/", label: "Dashboard", icon: "◫" },
  { to: "/demo", label: "Attack demo", icon: "▶" },
  { to: "/worlds", label: "Three worlds", icon: "≡" },
  { to: "/graph", label: "Provenance graph", icon: "⌘" },
  { to: "/guard", label: "Guard decisions", icon: "⛨" },
  { to: "/approvals", label: "Approvals", icon: "✋" },
  { to: "/warden", label: "Warden", icon: "⚕" },
  { to: "/metrics", label: "Metrics", icon: "≋" },
];

export function Layout({ children }: { children: ReactNode }) {
  const health = useHealth();
  const approvals = useApprovals();
  const [open, setOpen] = useState(false);
  const pending = approvals.data?.pending.length ?? 0;
  const ok = health.data?.falkordb;
  return (
    <div className="app">
      <aside className={`sidebar ${open ? "open" : ""}`}>
        <div className="brand">
          <span className="logo" aria-hidden>
            ◆
          </span>
          <div>
            <div className="brand-name">Custody</div>
            <div className="brand-sub">provenance for agent teams</div>
          </div>
          <button
            className="btn ghost menu"
            onClick={() => setOpen(!open)}
            aria-label="Toggle menu"
          >
            ☰
          </button>
        </div>
        <nav onClick={() => setOpen(false)}>
          {NAV.map((n) => (
            <NavLink key={n.to} to={n.to} end={n.to === "/"} className="nav-item">
              <span className="nav-icon" aria-hidden>
                {n.icon}
              </span>
              {n.label}
              {n.to === "/approvals" && pending > 0 && <span className="pill">{pending}</span>}
            </NavLink>
          ))}
        </nav>
        <div className="sidebar-foot">
          <div className="small">
            tenant <span className="mono">{TENANT}</span> · Acme Robotics
          </div>
          <div className="small">
            <span className={`dot ${ok ? "ok" : health.isLoading ? "" : "bad"}`} /> FalkorDB{" "}
            {health.isLoading ? "…" : ok ? "connected" : "unreachable"}
          </div>
          <div className="small muted">Guard: deterministic graph queries, no LLM</div>
          <div className="small muted">Acme Robotics is synthetic; integrations are simulated</div>
        </div>
      </aside>
      <main className="main">
        <SimulationBanner publicDemo={health.data?.public_demo === true} />
        {children}
      </main>
    </div>
  );
}

/** Always-visible disclosure: what in this demo is simulated, and public-demo status. */
export function SimulationBanner({ publicDemo }: { publicDemo: boolean }) {
  const reset = useReset();
  return (
    <div className="sim-banner" role="note" data-testid="simulation-banner">
      <span className="sim-text">
        <strong>Simulation.</strong> Acme Robotics is a synthetic company. The web pages, email,
        Slack, vault, GitHub and the attacker&apos;s server are simulated in-process (nothing is
        sent anywhere); &ldquo;Day 1&rdquo; and &ldquo;Day 4&rdquo; are simulated sessions; the
        agents follow scripted flows (or replay a recorded LLM run, when the demo says so). The
        provenance graph and every Guard decision are real.
      </span>
      {publicDemo && (
        <>
          <span className="public-tag" data-testid="public-demo-tag">
            Public demo · read-only
          </span>
          <button
            className="btn"
            data-testid="reset-demo"
            disabled={reset.isPending}
            onClick={() => reset.mutate()}
            title="Restore the initial demo state (identical every time)"
          >
            {reset.isPending ? "Resetting…" : "↺ Reset Demo"}
          </button>
          {reset.error && <span className="small">{(reset.error as Error).message}</span>}
        </>
      )}
    </div>
  );
}
