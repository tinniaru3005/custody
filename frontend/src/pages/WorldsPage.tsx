import { useBuildWorlds, usePublicDemo, useWorlds } from "../api/hooks";
import type { ChainNode, World } from "../api/types";
import { Empty, ErrorState, Loading, VerdictBadge } from "../components/ui";
import { fmtMs } from "../lib/format";

function shortFp(fp: string) {
  return fp.replace("sha256:", "").slice(0, 12);
}

function Chain({ nodes }: { nodes: ChainNode[] }) {
  return (
    <ol className="world-chain" data-testid="world-chain">
      {nodes.map((n) => {
        const isSource = !!n.trust;
        return (
          <li key={n.id} className={isSource ? `src src-${n.trust}` : ""}>
            {n.op && <span className="world-op mono">{n.op} ↓</span>}
            <span className="mono small">{isSource ? n.id : (n.kind ?? "datum")}</span>
            {n.agent && (
              <span className="muted small">
                {" "}
                · {n.agent}
                {n.session_id ? `@${n.session_id}` : ""}
              </span>
            )}
            {isSource && (
              <span className={`flag flag-${n.trust === "untrusted" ? "untrusted" : "trusted"}`}>
                {n.trust}
              </span>
            )}
          </li>
        );
      })}
    </ol>
  );
}

function WorldCard({ w }: { w: World }) {
  return (
    <section className={`world v-${w.verdict}`} data-testid={`world-${w.key}`}>
      <header>
        <div className="world-title">{w.title}</div>
        <div className="muted small">{w.subtitle}</div>
      </header>
      <div className="world-verdict">
        <VerdictBadge verdict={w.verdict} large />
      </div>
      <div className="world-dest small">
        destination <code>{w.destination}</code>
        <div className="muted mono">{shortFp(w.destination_fingerprint)}…</div>
      </div>
      <h4 className="section-title">History</h4>
      <ul className="small world-history">
        {w.history.map((h) => (
          <li key={h}>{h}</li>
        ))}
      </ul>
      <h4 className="section-title">Where the destination came from</h4>
      <Chain nodes={w.provenance} />
      <p className="small world-why" data-testid="world-why">
        {w.why}
      </p>
      <div className="muted small">
        Guard {fmtMs(w.latency_ms)} · action <span className="mono">{w.action_id}</span>
        {w.certificate && " · completeness certificate issued"}
      </div>
    </section>
  );
}

export function WorldsPage() {
  const q = useWorlds();
  const build = useBuildWorlds();
  const publicDemo = usePublicDemo();
  if (q.isLoading) return <Loading label="Loading the three worlds…" />;
  if (q.error) return <ErrorState error={q.error} onRetry={() => q.refetch()} />;
  const r = q.data;
  return (
    <div className="page">
      <header className="page-head">
        <div>
          <h1>Three worlds</h1>
          <p className="muted">
            The same Day-4 request, the same destination bytes and the same key, recorded in three
            different histories.
          </p>
        </div>
        {!publicDemo && (
          <button
            className="btn"
            onClick={() => build.mutate()}
            disabled={build.isPending}
            data-testid="build-worlds"
          >
            {build.isPending ? "Building…" : r ? "↻ Rebuild" : "▶ Build the three worlds"}
          </button>
        )}
      </header>
      {build.error && <ErrorState error={build.error} />}
      {!r ? (
        <Empty title="Not built yet">
          Builds three small simulated histories in a separate graph and checks the same action in
          each.
        </Empty>
      ) : (
        <>
          <div className="worlds-headline" data-testid="worlds-message">
            {r.message}
          </div>
          <p className="small worlds-request">
            Sam (Day 4): <em>“{r.request}”</em> → Ops proposes{" "}
            <code>upload_backup(destination=…, payload=&lt;rotated key&gt;)</code>
            <br />
            Identical in all three: destination bytes{" "}
            <strong data-testid="same-destination">
              {r.identical_destination ? "✓ same" : "✕ differ"}
            </strong>{" "}
            · rotated key <strong>{r.identical_payload ? "✓ same" : "✕ differ"}</strong> · Day-4
            request <strong>✓ same</strong>
          </p>
          <div className="worlds-grid">
            {r.worlds.map((w) => (
              <WorldCard key={w.key} w={w} />
            ))}
          </div>
          <p className="small muted">
            Simulated, like the main demo: synthetic company, in-process vault and web, scripted
            agents. The three histories live in their own graph and share no provenance. The
            decisions are real Guard checks.
          </p>
        </>
      )}
    </div>
  );
}
