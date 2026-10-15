import { useEffect, useMemo, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import { search } from "./content";
import { pagePath } from "./nav";

/** Full-text search over every docs section (client-side, no service). */
export function DocsSearch({ onClose }: { onClose: () => void }) {
  const [q, setQ] = useState("");
  const [sel, setSel] = useState(0);
  const input = useRef<HTMLInputElement>(null);
  const navigate = useNavigate();
  const hits = useMemo(() => search(q), [q]);

  useEffect(() => {
    input.current?.focus();
    const prev = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    return () => {
      document.body.style.overflow = prev;
    };
  }, []);

  const go = (i: number) => {
    const h = hits[i];
    if (!h) return;
    navigate({ pathname: pagePath(h.page.slug), hash: h.anchor });
    onClose();
  };

  return (
    <div className="docs-search-overlay" onClick={onClose}>
      <div
        className="docs-search"
        role="dialog"
        aria-modal="true"
        aria-label="Search documentation"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="docs-search-field">
          <span aria-hidden>⌕</span>
          <input
            ref={input}
            value={q}
            placeholder="Search: guard, quarantine, CUSTODY_PUBLIC_DEMO…"
            aria-label="Search query"
            aria-controls="docs-search-results"
            onChange={(e) => {
              setQ(e.target.value);
              setSel(0);
            }}
            onKeyDown={(e) => {
              if (e.key === "ArrowDown") {
                e.preventDefault();
                setSel((s) => Math.min(s + 1, hits.length - 1));
              } else if (e.key === "ArrowUp") {
                e.preventDefault();
                setSel((s) => Math.max(s - 1, 0));
              } else if (e.key === "Enter") {
                go(sel);
              } else if (e.key === "Escape") {
                onClose();
              }
            }}
          />
          <kbd>Esc</kbd>
        </div>
        <ul id="docs-search-results" className="docs-search-results" role="listbox">
          {q.trim() && hits.length === 0 && (
            <li className="docs-search-empty">No section mentions “{q.trim()}”.</li>
          )}
          {hits.map((h, i) => (
            <li
              key={`${h.page.slug}#${h.anchor}`}
              role="option"
              aria-selected={i === sel}
              className={i === sel ? "sel" : ""}
              onMouseEnter={() => setSel(i)}
              onClick={() => go(i)}
            >
              <div className="hit-head">
                <span className="hit-page">{h.page.title}</span>
                {h.anchor && <span className="hit-heading">{h.heading}</span>}
              </div>
              <div className="hit-snippet">{h.snippet}</div>
            </li>
          ))}
          {!q.trim() && (
            <li className="docs-search-empty">
              Type to search every page. Use ↑ ↓ to move and Enter to open.
            </li>
          )}
        </ul>
      </div>
    </div>
  );
}
