import { useState } from "react";
import { Link } from "react-router-dom";
import {
  useApprovals,
  useApprove,
  useDatum,
  usePublicDemo,
  useReject,
  useSendDisclosure,
} from "../api/hooks";
import { api } from "../api/client";
import type { ApprovalItem } from "../api/types";
import { EndorsementFlip } from "../components/EndorsementFlip";
import { relKey, type Flip } from "../lib/flip";
import { ProvenanceChain } from "../components/ProvenanceChain";
import { Empty, ErrorState, Loading, Panel, StatusBadge, VerdictBadge } from "../components/ui";
import { CHECK_LABEL, fmtTime } from "../lib/format";

const DEFAULT_APPROVER = "priya@acme-robotics.example";

export function ApprovalsPage() {
  const q = useApprovals();
  const send = useSendDisclosure();
  const readOnly = usePublicDemo();
  const [approver, setApprover] = useState(DEFAULT_APPROVER);
  const [flips, setFlips] = useState<Flip[]>([]);
  const onApproved = (f: Flip) => {
    setFlips((xs) => [f, ...xs.filter((x) => x.actionId !== f.actionId)]);
    // read the new ENDORSES / APPROVES relationships back from the graph
    api
      .explain(f.actionId)
      .then((explain) =>
        setFlips((xs) => xs.map((x) => (x.actionId === f.actionId ? { ...x, explain } : x))),
      )
      .catch(() => undefined);
  };

  if (q.isLoading) return <Loading label="Loading approval queue…" />;
  if (q.error) return <ErrorState error={q.error} onRetry={() => q.refetch()} />;
  const { pending, blocked, resolved } = q.data!;

  return (
    <div className="page">
      <header className="page-head">
        <div>
          <h1>Approvals</h1>
          <p className="muted">
            The Guard asks a human only when policy allows it. Approvals and rejections are written
            into the graph (<code>ENDORSES</code>, <code>APPROVES</code>, <code>REJECTS</code>).
            Lethal-trifecta blocks never get an approve button.
          </p>
        </div>
        <label className="field">
          <span className="small muted">Signed in as (approver)</span>
          <input className="input" value={approver} onChange={(e) => setApprover(e.target.value)} />
        </label>
      </header>

      {flips.length > 0 && (
        <Panel
          title="Just approved: the decision flip"
          subtitle="A human decision is a graph write; the deterministic Guard re-runs on the new graph"
        >
          {flips.map((f) => (
            <EndorsementFlip key={f.actionId} f={f} />
          ))}
        </Panel>
      )}

      <Panel title={`Waiting for a human (${pending.length})`}>
        {pending.length === 0 ? (
          <Empty title="Nothing is waiting for approval" />
        ) : (
          <div className="stack">
            {pending.map((item) => (
              <PendingCard
                key={item.explain.action.id}
                item={item}
                approver={approver}
                onApproved={onApproved}
              />
            ))}
          </div>
        )}
      </Panel>

      <Panel
        title={`Blocked — cannot be approved (${blocked.length})`}
        subtitle="Untrusted destination + secret payload + external sink. The agent must propose something else."
      >
        {blocked.length === 0 ? (
          <Empty title="No blocked actions" />
        ) : (
          <div className="stack">
            {blocked.map((item) => (
              <article
                key={item.explain.action.id}
                className="approval-card blocked"
                data-testid="blocked-card"
              >
                <ApprovalHeader item={item} />
                <ProvenanceChain cards={item.explain.chain} compact />
                <p className="approval-note none">{item.why}</p>
                <Link to={`/guard/${item.explain.action.id}`} className="small">
                  Full decision →
                </Link>
              </article>
            ))}
          </div>
        )}
      </Panel>

      <Panel title={`Resolved (${resolved.length})`}>
        {resolved.length === 0 ? (
          <Empty title="No resolved approvals yet" />
        ) : (
          <table className="table">
            <tbody>
              {resolved.map((a) => (
                <tr key={a.id}>
                  <td className="mono">{a.action_type}</td>
                  <td>{a.agent}</td>
                  <td className="mono small">{a.destination}</td>
                  <td>
                    <VerdictBadge verdict={a.verdict} />
                  </td>
                  <td>
                    <StatusBadge status={a.status} />
                  </td>
                  <td>
                    {a.action_type === "send_disclosure" && a.status === "approved" ? (
                      <button
                        className="btn primary"
                        disabled={send.isPending || readOnly}
                        onClick={() => send.mutate(a.id)}
                        data-testid="send-disclosure"
                      >
                        Send disclosure
                      </button>
                    ) : (
                      <Link to={`/guard/${a.id}`} className="small">
                        decision →
                      </Link>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
        {send.data && (
          <p className={`small ${send.data.sent ? "ok-text" : "bad-text"}`} role="status">
            {send.data.sent
              ? `Sent to ${send.data.destination}: ${send.data.detail}`
              : send.data.detail}
          </p>
        )}
        {send.error && <ErrorState error={send.error} />}
      </Panel>
    </div>
  );
}

function ApprovalHeader({ item }: { item: ApprovalItem }) {
  const a = item.explain.action;
  const d = item.explain.decision;
  return (
    <header className="row between wrap">
      <div>
        <div className="row tight">
          <VerdictBadge verdict={d.decision} />
          <strong className="mono">{a.action_type}</strong>
          <span className="muted">by {a.agent}</span>
        </div>
        <div className="small muted">
          to <span className="mono">{a.destination ?? "—"}</span> ·{" "}
          {a.sim_time ? fmtTime(a.sim_time) : fmtTime(a.created_at)} · session {a.session_id}
        </div>
      </div>
      <StatusBadge status={a.status} />
    </header>
  );
}

function PendingCard({
  item,
  approver,
  onApproved,
}: {
  item: ApprovalItem;
  approver: string;
  onApproved?: (f: Flip) => void;
}) {
  const approve = useApprove();
  const reject = useReject();
  const readOnly = usePublicDemo();
  const [reason, setReason] = useState("");
  const a = item.explain.action;
  const d = item.explain.decision;
  const isDisclosure = a.action_type === "send_disclosure";
  const draftId =
    typeof a.metadata?.draft_id === "string" ? (a.metadata.draft_id as string) : undefined;
  const busy = approve.isPending || reject.isPending;
  const hasPath = item.explain.chain.length > 2;
  return (
    <article className="approval-card" data-testid="pending-card">
      <ApprovalHeader item={item} />
      <div className="why">
        <h4>Why approval is needed</h4>
        <ul>
          {d.triggered_checks.map((c) => (
            <li key={c}>
              <strong>{CHECK_LABEL[c]}:</strong> {d.checks[c]?.detail}
            </li>
          ))}
        </ul>
        <p className="small muted">{item.why}</p>
      </div>
      {hasPath && (
        <>
          <h4>The risky path</h4>
          <ProvenanceChain cards={item.explain.chain} compact />
        </>
      )}
      {isDisclosure && draftId && (
        <DraftPreview id={draftId} subject={String(a.metadata?.subject ?? "")} />
      )}
      {item.can_approve ? (
        <div className="approve-row">
          <input
            className="input"
            placeholder="Reason (recorded in the graph)"
            value={reason}
            onChange={(e) => setReason(e.target.value)}
            aria-label="Reason"
          />
          <button
            className="btn danger"
            disabled={busy || readOnly}
            title={readOnly ? "Public demo is read-only" : undefined}
            onClick={() => reject.mutate({ actionId: a.id, approver, reason })}
            data-testid="reject"
          >
            Reject
          </button>
          <button
            className="btn approve"
            disabled={busy || readOnly || !approver.trim()}
            title={readOnly ? "Public demo is read-only" : undefined}
            onClick={() => {
              approve.mutate(
                { actionId: a.id, approver, reason },
                {
                  onSuccess: (after) =>
                    onApproved?.({
                      actionId: a.id,
                      actionType: a.action_type,
                      before: d.decision,
                      beforeTriggered: d.triggered_checks,
                      after,
                      knownBefore: item.explain.approvals.map(relKey),
                    }),
                },
              );
            }}
            data-testid="approve"
          >
            Approve
          </button>
        </div>
      ) : (
        <p className="approval-note none">{item.why}</p>
      )}
      {(approve.error || reject.error) && <ErrorState error={approve.error ?? reject.error} />}
    </article>
  );
}

function DraftPreview({ id, subject }: { id: string; subject: string }) {
  const q = useDatum(id);
  if (q.isLoading) return <Loading label="Loading draft…" />;
  if (!q.data) return null;
  return (
    <details className="draft" open>
      <summary>
        Disclosure draft written by the Warden (nothing is sent until you approve and send)
      </summary>
      <pre>
        {subject ? `Subject: ${subject}\n\n` : ""}
        {q.data.value ?? q.data.preview}
      </pre>
    </details>
  );
}
