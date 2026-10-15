import { useCallback, useEffect, useMemo, useRef, useState, type MouseEvent } from "react";
import { Link, NavLink, useLocation, useNavigate, useParams } from "react-router-dom";
import { loadPage } from "./content";
import { DocsSearch } from "./DocsSearch";
import { DOCS_BASE, PAGES, REPO_URL, SECTIONS, pagePath, sectionOf } from "./nav";
import "./docs.css";

type Theme = "dark" | "light";
const THEME_KEY = "custody-docs-theme";
const IS_MAC = typeof navigator !== "undefined" && /Mac|iPhone|iPad/.test(navigator.userAgent);

function initialTheme(): Theme {
  try {
    const saved = localStorage.getItem(THEME_KEY);
    if (saved === "dark" || saved === "light") return saved;
  } catch {
    /* storage unavailable: fall through to the system preference */
  }
  if (typeof window !== "undefined" && window.matchMedia?.("(prefers-color-scheme: light)").matches)
    return "light";
  return "dark";
}

export default function DocsApp() {
  const { "*": rest = "" } = useParams();
  const slug = rest.replace(/\/+$/, "") || "overview";
  const page = PAGES.find((p) => p.slug === slug);
  const doc = page ? loadPage(slug) : undefined;
  const location = useLocation();
  const navigate = useNavigate();
  const [theme, setTheme] = useState<Theme>(initialTheme);
  const [navOpen, setNavOpen] = useState(false);
  const [searchOpen, setSearchOpen] = useState(false);
  const [zoom, setZoom] = useState<string | null>(null);
  const [active, setActive] = useState<string>("");
  const articleRef = useRef<HTMLElement>(null);

  const toggleTheme = () => {
    const next: Theme = theme === "dark" ? "light" : "dark";
    setTheme(next);
    try {
      localStorage.setItem(THEME_KEY, next);
    } catch {
      /* not persisted */
    }
  };

  // title, and scroll to the hash (or the top) whenever the page or hash changes
  useEffect(() => {
    document.title = page ? `${page.title} · Custody docs` : "Not found · Custody docs";
    const id = decodeURIComponent(location.hash.slice(1));
    const frame = requestAnimationFrame(() => {
      const el = id ? document.getElementById(id) : null;
      if (el) el.scrollIntoView({ block: "start" });
      else window.scrollTo(0, 0);
    });
    return () => cancelAnimationFrame(frame);
  }, [page, location.pathname, location.hash]);

  // highlight the section being read in the table of contents
  useEffect(() => {
    const root = articleRef.current;
    if (!root || typeof IntersectionObserver === "undefined") return;
    const hs = Array.from(root.querySelectorAll<HTMLElement>("h2[id], h3[id]"));
    const obs = new IntersectionObserver(
      (entries) => {
        const visible = entries.filter((e) => e.isIntersecting);
        if (visible.length) setActive(visible[0].target.id);
      },
      { rootMargin: "0px 0px -72% 0px" },
    );
    hs.forEach((h) => obs.observe(h));
    return () => obs.disconnect();
  }, [doc]);

  // keyboard: Ctrl/Cmd+K or "/" opens search, Escape closes overlays
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const t = e.target;
      const typing =
        t instanceof Element && t.closest("input, textarea, select, [contenteditable]");
      if ((e.key === "k" && (e.metaKey || e.ctrlKey)) || (e.key === "/" && !typing)) {
        e.preventDefault();
        setSearchOpen(true);
      } else if (e.key === "Escape") {
        setZoom(null);
        setNavOpen(false);
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  /** In-content clicks: client-side links, copy buttons, screenshot zoom. */
  const onArticleClick = useCallback(
    (e: MouseEvent<HTMLElement>) => {
      const target = e.target as HTMLElement;
      const copy = target.closest<HTMLButtonElement>("[data-copy]");
      if (copy) {
        const code = copy.closest(".code-block")?.querySelector("pre")?.textContent ?? "";
        const done = (ok: boolean) => {
          copy.textContent = ok ? "Copied" : "Copy failed";
          copy.classList.toggle("done", ok);
          window.setTimeout(() => {
            copy.textContent = "Copy";
            copy.classList.remove("done");
          }, 1600);
        };
        if (navigator.clipboard?.writeText)
          navigator.clipboard.writeText(code).then(
            () => done(true),
            () => done(false),
          );
        else done(false);
        return;
      }
      const z = target.closest<HTMLElement>("[data-zoom]");
      if (z) {
        setZoom(z.dataset.zoom ?? null);
        return;
      }
      const a = target.closest<HTMLAnchorElement>("a");
      if (!a || a.target === "_blank" || e.metaKey || e.ctrlKey || e.shiftKey) return;
      const href = a.getAttribute("href") ?? "";
      if (href.startsWith("#")) {
        e.preventDefault();
        navigate({ pathname: location.pathname, hash: href }, { replace: false });
      } else if (href.startsWith("/") && !href.startsWith("/api/")) {
        e.preventDefault();
        navigate(href);
      }
    },
    [navigate, location.pathname],
  );

  const idx = page ? PAGES.indexOf(page) : -1;
  const prev = idx > 0 ? PAGES[idx - 1] : undefined;
  const next = idx >= 0 && idx < PAGES.length - 1 ? PAGES[idx + 1] : undefined;
  const toc = useMemo(() => (doc ? doc.headings.filter((h) => h.depth <= 3) : []), [doc]);
  const section = page ? sectionOf(page.slug) : undefined;

  return (
    <div className="docs" data-theme={theme}>
      <a className="skip-link" href="#doc-content">
        Skip to content
      </a>
      <header className="docs-top">
        <button
          type="button"
          className="docs-icon-btn docs-menu"
          aria-label="Open navigation"
          aria-expanded={navOpen}
          onClick={() => setNavOpen(!navOpen)}
        >
          <span aria-hidden>☰</span>
        </button>
        <Link to={DOCS_BASE} className="docs-brand">
          <span className="docs-logo" aria-hidden>
            ◆
          </span>
          <span>Custody</span>
          <span className="docs-brand-sub">documentation</span>
        </Link>
        <button type="button" className="docs-search-btn" onClick={() => setSearchOpen(true)}>
          <span aria-hidden>⌕</span>
          <span className="docs-search-label">Search the docs</span>
          <kbd>{IS_MAC ? "⌘ K" : "Ctrl K"}</kbd>
        </button>
        <nav className="docs-top-links" aria-label="Site">
          <Link to="/" className="docs-top-link">
            Console
          </Link>
          <a className="docs-top-link" href={REPO_URL} target="_blank" rel="noopener noreferrer">
            GitHub
          </a>
          <button
            type="button"
            className="docs-icon-btn"
            onClick={toggleTheme}
            aria-label={theme === "dark" ? "Switch to light theme" : "Switch to dark theme"}
            title={theme === "dark" ? "Light theme" : "Dark theme"}
          >
            <span aria-hidden>{theme === "dark" ? "☀" : "☾"}</span>
          </button>
        </nav>
      </header>

      <div className="docs-body">
        <aside className={`docs-nav ${navOpen ? "open" : ""}`} aria-label="Documentation">
          <nav onClick={(e) => (e.target as HTMLElement).closest("a") && setNavOpen(false)}>
            {SECTIONS.map((s) => (
              <div key={s.title} className="docs-nav-section">
                <div className="docs-nav-title">{s.title}</div>
                <ol className="docs-trail">
                  {s.pages.map((p) => (
                    <li key={p.slug}>
                      <NavLink to={pagePath(p.slug)} end className="docs-nav-link">
                        {p.title}
                      </NavLink>
                    </li>
                  ))}
                </ol>
              </div>
            ))}
          </nav>
        </aside>
        {navOpen && <div className="docs-scrim" onClick={() => setNavOpen(false)} aria-hidden />}

        <main className="docs-main" id="doc-content">
          {page && doc ? (
            <article className="docs-article" ref={articleRef} onClick={onArticleClick}>
              {section && <div className="docs-crumb">{section.title}</div>}
              <div className="docs-prose" dangerouslySetInnerHTML={{ __html: doc.html }} />
              <footer className="docs-foot">
                <div className="docs-pager">
                  {prev ? (
                    <Link className="pager prev" to={pagePath(prev.slug)}>
                      <span className="pager-dir">Previous</span>
                      <span className="pager-title">{prev.title}</span>
                    </Link>
                  ) : (
                    <span />
                  )}
                  {next && (
                    <Link className="pager next" to={pagePath(next.slug)}>
                      <span className="pager-dir">Next</span>
                      <span className="pager-title">{next.title}</span>
                    </Link>
                  )}
                </div>
                <a
                  className="docs-edit"
                  href={`${REPO_URL}/blob/main/frontend/src/docs/content/${page.slug}.md`}
                  target="_blank"
                  rel="noopener noreferrer"
                >
                  Edit this page on GitHub
                </a>
              </footer>
            </article>
          ) : (
            <article className="docs-article">
              <div className="docs-prose">
                <h1>Page not found</h1>
                <p>
                  There is no documentation page at <code>{location.pathname}</code>. Use search or
                  start from the <Link to={DOCS_BASE}>overview</Link>.
                </p>
              </div>
            </article>
          )}
        </main>

        <aside className="docs-toc" aria-label="On this page">
          {toc.length > 0 && (
            <>
              <div className="docs-toc-title">On this page</div>
              <ul>
                {toc.map((h) => (
                  <li key={h.id} className={`d${h.depth} ${active === h.id ? "active" : ""}`}>
                    <a
                      href={`#${h.id}`}
                      onClick={(e) => {
                        e.preventDefault();
                        navigate({ pathname: location.pathname, hash: h.id });
                      }}
                    >
                      {h.text}
                    </a>
                  </li>
                ))}
              </ul>
            </>
          )}
        </aside>
      </div>

      {searchOpen && <DocsSearch onClose={() => setSearchOpen(false)} />}
      {zoom && (
        <div
          className="docs-lightbox"
          role="dialog"
          aria-modal="true"
          aria-label="Screenshot"
          onClick={() => setZoom(null)}
        >
          <img src={zoom} alt="" />
          <button type="button" className="docs-icon-btn lightbox-close" aria-label="Close">
            ✕
          </button>
        </div>
      )}
    </div>
  );
}
