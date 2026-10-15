import { Fragment } from "react";
import { Link } from "react-router-dom";
import type { ChainCard } from "../api/types";
import { truncate } from "../lib/format";

const OP_TEXT: Record<string, string> = {
  TO: "sends to",
  FROM: "came from",
  derive: "derived from",
  recall: "recall of",
  save: "saved from",
  send: "sent from",
  attribute: "exact value of",
  extract: "extracted from",
};

function opLabel(op?: string) {
  if (!op) return "";
  if (op.startsWith("ARG:")) return `argument: ${op.slice(4)}`;
  return OP_TEXT[op] ?? op;
}

function cardTone(c: ChainCard): string {
  if (c.role === "action")
    return c.verdict === "BLOCK" ? "block" : c.verdict === "ALLOW" ? "allow" : "approval";
  if (c.role === "sink") return c.external ? "block" : "allow";
  if (c.role === "source") return c.trust === "untrusted" ? "block" : "allow";
  if (c.sensitivity === "secret") return "secret";
  if (c.endorsed) return "allow";
  return "tainted";
}

/**
 * The hero visualisation: one concrete provenance route behind the decision (the
 * shortest uncleared one; the verdict itself checks every route),
 * from the proposed Action to the Source it ultimately came from, with every hop's
 * edge type and every session boundary called out.
 */
export function ProvenanceChain({
  cards,
  compact,
  pathStatus,
}: {
  cards: ChainCard[];
  compact?: boolean;
  pathStatus?: string;
}) {
  if (!cards.length) return null;
  const clean = cards.length <= 2;
  return (
    <div className={`chain ${compact ? "compact" : ""}`} data-testid="provenance-chain">
      {cards.map((c, i) => {
        const prev = cards[i - 1];
        const sessionBreak =
          prev && prev.session_id && c.session_id && prev.session_id !== c.session_id;
        return (
          <Fragment key={`${c.id}-${i}`}>
            {i > 0 && (
              <div className="chain-link" aria-hidden={false}>
                <span className="chain-arrow">→</span>
                <span className="chain-op">{opLabel(c.op)}</span>
                {sessionBreak && (
                  <span className="session-break" title="the path crosses a session boundary">
                    ⟲ crosses into {c.session_id}
                  </span>
                )}
              </div>
            )}
            <Link
              to={`/graph?focus=${encodeURIComponent(c.id)}`}
              className={`chain-card tone-${cardTone(c)}`}
              data-role={c.role}
              title={c.title}
            >
              <span className="chain-role">{c.role}</span>
              <span className="chain-kind">
                {c.label}
                {c.agent ? ` · ${c.agent}` : ""}
                {c.session_id ? ` · ${c.session_id}` : ""}
              </span>
              <span className="chain-title">{truncate(c.title, compact ? 70 : 110)}</span>
              <span className="chain-tags">
                {c.role === "source" && <span className={`flag flag-${c.trust}`}>{c.trust}</span>}
                {c.role === "sink" && (
                  <span className={`flag flag-${c.external ? "external" : "internal"}`}>
                    {c.external ? "external" : "internal"}
                  </span>
                )}
                {c.sensitivity === "secret" && <span className="flag flag-secret">secret</span>}
                {c.endorsed && <span className="flag flag-endorsed">endorsed</span>}
                {c.role === "action" && c.path_length !== undefined && (
                  <span className="flag">{c.path_length} DERIVED_FROM hops</span>
                )}
              </span>
            </Link>
          </Fragment>
        );
      })}
      {clean && (
        <p className="muted small chain-note">
          {pathStatus === "info"
            ? "No untrusted provenance on the destination."
            : "No provenance path to an untrusted source was found for this action's destination."}
        </p>
      )}
    </div>
  );
}
