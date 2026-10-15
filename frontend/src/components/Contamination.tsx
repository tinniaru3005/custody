import type { ContaminationReport } from "../api/types";

const ROUTES: Record<string, (c: ContaminationReport) => string> = {
  independent: (c) =>
    `Independent routes: yes — ${c.independent_routes}+ routes share no node besides the argument (verified).`,
  converging: (c) => {
    const n = c.roots.flatMap((r) => r.path.nodes).find((x) => x.id === c.shared_datum_id);
    const what = n ? `${n.kind ?? "datum"} ${n.id}` : c.shared_datum_id;
    return `Independent routes: no — every route passes through ${what} (verified).`;
  },
  direct: () => "The argument itself is untrusted content.",
  unverified: () => "Independent routes: not verified (search budget reached).",
};

/** Every distinct untrusted root of the destination, one route each, and whether the
 * routes are independent. Explanation only: the verdict checks every route. */
export function ContaminationSection({
  c,
  actionId,
}: {
  c?: ContaminationReport | null;
  actionId: string;
}) {
  if (!c || c.root_count === 0) return null;
  return (
    <section className="contamination" data-testid="contamination">
      <h3 className="section-title">
        Untrusted roots detected: {c.roots_complete ? "" : "at least "}
        {c.root_count}
      </h3>
      <ul className="roots">
        {c.roots.map((r, i) => (
          <li key={r.source_id} data-testid="root">
            <strong>Source {String.fromCharCode(65 + (i % 26))}:</strong>{" "}
            <span className="mono">{r.source_id}</span>{" "}
            <span className="muted small">
              ({r.source_kind ?? "?"}, {r.hops} hop{r.hops === 1 ? "" : "s"} via{" "}
              {r.path.agents.join(" → ") || "—"})
            </span>
            <details>
              <summary className="small">representative route</summary>
              <code className="small">{r.path.text}</code>
            </details>
          </li>
        ))}
      </ul>
      {c.root_count > 1 && (
        <p className="small">
          {c.root_count === 2 ? "Both" : "All"} influenced action{" "}
          <span className="mono">{actionId}</span>.
        </p>
      )}
      <p className="small" data-testid="independence">
        {(ROUTES[c.independence] ?? ROUTES.unverified)(c)}
      </p>
      <p className="muted small">{c.note}</p>
    </section>
  );
}
