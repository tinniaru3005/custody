import { useState } from "react";
import { useChokepoints } from "../api/hooks";
import { ErrorState, Loading } from "./ui";

/** Warden chokepoint analysis for a non-ALLOW decision, loaded when opened. */
export function ChokepointsSection({ actionId }: { actionId: string }) {
  const [open, setOpen] = useState(false);
  const q = useChokepoints(actionId, open);
  return (
    <details
      className="paths"
      data-testid="chokepoints"
      onToggle={(e) => setOpen((e.target as HTMLDetailsElement).open)}
    >
      <summary>Chokepoints: which single node breaks every untrusted path? (Warden)</summary>
      {q.isLoading && <Loading label="Excluding each candidate and re-running the search…" />}
      {q.error && <ErrorState error={q.error} />}
      {q.data && (
        <div className="small">
          <p>{q.data.summary}</p>
          <ul>
            {q.data.chokepoints
              .filter((c) => !c.trivial)
              .map((c) => (
                <li key={c.id} data-testid="chokepoint">
                  <span className="mono">{c.id}</span>
                  {c.id === q.data!.recommended && <strong> · recommended</strong>}
                  <div className="muted">{c.explanation}</div>
                </li>
              ))}
          </ul>
          <p className="muted">Method: {q.data.method}.</p>
        </div>
      )}
    </details>
  );
}
