import { ContaminationSection } from "./Contamination";
import type { ActionExplain, CheckName, CheckResult, GuardDecision } from "../api/types";
import { CHECK_LABEL, fmtMs, fmtTime } from "../lib/format";
import { CertificateSection } from "./Certificate";
import { ChokepointsSection } from "./Chokepoints";
import { ProvenanceChain } from "./ProvenanceChain";
import { StatusBadge, VerdictBadge } from "./ui";

const CHECK_ORDER: CheckName[] = [
  "integrity",
  "confidentiality",
  "lethal_trifecta",
  "human_review",
  "precedent",
];

function CheckCard({ c }: { c: CheckResult }) {
  const state = !c.evaluated ? "skip" : c.violated ? "fail" : c.raw_violation ? "cleared" : "pass";
  const text = {
    skip: "not applicable",
    fail: "VIOLATED",
    cleared: "cleared by approval",
    pass: "passed",
  }[state];
  return (
    <div className={`check check-${state}`} data-testid={`check-${c.name}`}>
      <div className="check-head">
        <span className="check-name">{CHECK_LABEL[c.name]}</span>
        <span className="check-state">
          {state === "fail" ? "✕ " : state === "skip" ? "– " : "✓ "}
          {text}
        </span>
      </div>
      <p className="small">{c.detail}</p>
      {!!c.precedents?.length && (
        <div className="small" data-testid="precedent">
          {c.precedents.map((p) => (
            <div key={p.approval_id}>
              Rejected by {p.approver}
              {p.reason ? ` (“${p.reason}”)` : ""}: <code>{p.relationship}</code>
            </div>
          ))}
        </div>
      )}
      <div className="muted small mono">
        {c.query ? `query: ${c.query}` : ""}
        {c.latency_ms ? ` · ${fmtMs(c.latency_ms)}` : ""}
      </div>
    </div>
  );
}

/** The three conditions of the lethal trifecta, shown as a checklist. */
export function Trifecta({ d }: { d: GuardDecision }) {
  const integrity = d.checks.integrity?.raw_violation ?? false;
  const secret = (d.checks.confidentiality?.paths.length ?? 0) > 0;
  const external = d.sink.external;
  const items = [
    { on: integrity, text: "Untrusted influence on the destination", sub: "integrity_paths" },
    { on: secret, text: "Secret data in the payload", sub: "confidentiality_paths" },
    { on: external, text: "External sink", sub: d.sink.reason },
  ];
  const all = items.every((i) => i.on);
  return (
    <div className={`trifecta ${all ? "hit" : ""}`} data-testid="trifecta">
      <div className="trifecta-title">
        Lethal trifecta{" "}
        {all ? (
          <strong>— all three present → BLOCK</strong>
        ) : (
          <span className="muted">— not all present</span>
        )}
      </div>
      <ol>
        {items.map((i) => (
          <li key={i.text} className={i.on ? "on" : "off"}>
            <span aria-hidden>{i.on ? "●" : "○"}</span> {i.text}
            <span className="muted small"> · {i.sub}</span>
          </li>
        ))}
      </ol>
    </div>
  );
}

export function LatencyBars({
  latency,
  totalLabel = "total",
}: {
  latency: Record<string, number>;
  totalLabel?: string;
}) {
  const entries = Object.entries(latency).filter(([k]) => k !== "total");
  const max = Math.max(...entries.map(([, v]) => v), 0.001);
  return (
    <div className="latency" aria-label="Guard latency breakdown">
      {entries.map(([k, v]) => (
        <div key={k} className="lat-row" title={`${k}: ${fmtMs(v)}`}>
          <span className="lat-name mono">{k}</span>
          <span className="lat-bar">
            <span style={{ width: `${Math.max(3, (v / max) * 100)}%` }} />
          </span>
          <span className="lat-val mono">{fmtMs(v)}</span>
        </div>
      ))}
      <div className="lat-row total">
        <span className="lat-name mono">{totalLabel}</span>
        <span />
        <span className="lat-val mono">{fmtMs(latency.total)}</span>
      </div>
    </div>
  );
}

export function DecisionDetail({ ex }: { ex: ActionExplain }) {
  const d = ex.decision;
  const head = ex.chain[0];
  return (
    <div className="decision" data-testid="decision-detail">
      <div className={`verdict-banner v-${d.decision}`}>
        <div>
          <VerdictBadge verdict={d.decision} large />
          <h2>
            {d.action_type} <span className="muted">by {d.agent}</span>
          </h2>
          <div className="muted small">
            to <span className="mono">{d.sink.destination ?? "no sink"}</span> · status{" "}
            <StatusBadge status={ex.action.status} /> · policy {d.policy}
          </div>
        </div>
        <div className="banner-right">
          <div className="big-num">{fmtMs(d.latency_ms.total)}</div>
          <div className="muted small">Guard check · deterministic · no LLM</div>
        </div>
      </div>
      <p className="explanation">{d.explanation}</p>
      <CertificateSection d={d} />

      <h3 className="section-title">Why: the shortest uncleared provenance route</h3>
      <ProvenanceChain cards={ex.chain} pathStatus={head?.path_status} />
      <ContaminationSection c={d.contamination} actionId={d.action_id} />

      <div className="grid-2">
        <div>
          <h3 className="section-title">Checks</h3>
          <div className="checks">
            {CHECK_ORDER.filter((k) => d.checks[k]).map((k) => (
              <CheckCard key={k} c={d.checks[k]} />
            ))}
          </div>
        </div>
        <div>
          <h3 className="section-title">Lethal trifecta</h3>
          <Trifecta d={d} />
          <h3 className="section-title">Sink</h3>
          <p className="small">
            <span className="mono">{d.sink.destination ?? "—"}</span> ({d.sink.kind ?? "none"}) →{" "}
            <strong>{d.sink.zone}</strong>: {d.sink.reason}
            {d.sink.bound === false && (
              <span className="flag flag-untrusted"> unbound destination</span>
            )}
          </p>
          <h3 className="section-title">Approval</h3>
          <p
            className={`small approval-note ${d.approval.available ? "" : "none"}`}
            data-testid="approval-option"
          >
            {d.approval.available ? "Approval possible: " : "No approval option: "}
            {d.approval.reason}
          </p>
          <h3 className="section-title">Latency</h3>
          <LatencyBars latency={d.latency_ms} />
        </div>
      </div>

      {d.decision !== "ALLOW" && <ChokepointsSection actionId={d.action_id} />}

      {d.paths.length > 0 && (
        <details className="paths">
          <summary>All {d.paths.length} provenance path(s) the queries returned</summary>
          <ul>
            {d.paths.map((p, i) => (
              <li key={i}>
                <span className={`flag flag-${p.status === "violating" ? "untrusted" : "trusted"}`}>
                  {p.check}/{p.status}
                </span>{" "}
                <code>{p.text}</code>
              </li>
            ))}
          </ul>
        </details>
      )}

      {(ex.history.length > 0 || ex.approvals.length > 0) && (
        <div className="grid-2">
          <div>
            <h3 className="section-title">Decision audit trail (graph)</h3>
            <ul className="audit">
              {ex.history.map((h) => (
                <li key={h.id}>
                  <VerdictBadge verdict={h.decision} />{" "}
                  <span className="muted small">{fmtTime(h.created_at)}</span>{" "}
                  <span className="mono small">{fmtMs(h.latency_ms)}</span>
                </li>
              ))}
            </ul>
          </div>
          <div>
            <h3 className="section-title">Human decisions (graph)</h3>
            {ex.approvals.length ? (
              <ul className="audit">
                {ex.approvals.map((a) => (
                  <li key={a.id + a.relation}>
                    <span className="mono small">{a.relation}</span> by {a.approver}
                    {a.reason ? ` — “${a.reason}”` : ""}{" "}
                    <span className="muted small">{fmtTime(a.created_at)}</span>
                  </li>
                ))}
              </ul>
            ) : (
              <p className="muted small">none</p>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
