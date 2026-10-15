import { renderMarkdown, stripTags, type RenderedDoc } from "./markdown";
import { PAGES, type DocPage } from "./nav";

const RAW = import.meta.glob("./content/*.md", {
  eager: true,
  query: "?raw",
  import: "default",
}) as Record<string, string>;

export function rawPage(slug: string): string | undefined {
  return RAW[`./content/${slug}.md`];
}

const cache = new Map<string, RenderedDoc>();

export function loadPage(slug: string): RenderedDoc | undefined {
  const hit = cache.get(slug);
  if (hit) return hit;
  const raw = rawPage(slug);
  if (raw === undefined) return undefined;
  const doc = renderMarkdown(raw);
  cache.set(slug, doc);
  return doc;
}

export interface SearchEntry {
  page: DocPage;
  /** heading id, or "" for the top of the page */
  anchor: string;
  heading: string;
  text: string;
}

let index: SearchEntry[] | null = null;

/** One entry per page section (split at h2/h3), built lazily from the rendered pages. */
export function searchIndex(): SearchEntry[] {
  if (index) return index;
  const out: SearchEntry[] = [];
  for (const page of PAGES) {
    const doc = loadPage(page.slug);
    if (!doc) continue;
    const parts = doc.html.split(/(?=<h[23] id=")/);
    for (const part of parts) {
      const m = part.match(/^<h[23] id="([^"]+)">([\s\S]*?)<\/h[23]>/);
      const heading = m ? stripTags(m[2]).replace(/^#/, "").trim() : page.title;
      const html = (m ? part.slice(m[0].length) : part).replace(
        /<\/(td|th|li|p|tr|div|pre|figcaption|h[1-6])>|<br\s*\/?>/g,
        "$& ",
      );
      const body = stripTags(html)
        .replace(/\bCopy\b/g, " ")
        .replace(/\s+/g, " ")
        .trim();
      out.push({ page, anchor: m ? m[1] : "", heading, text: body });
    }
  }
  index = out;
  return out;
}

export interface SearchHit extends SearchEntry {
  score: number;
  snippet: string;
}

/** Every query term must appear in the page title, the heading or the section text. */
export function search(query: string, limit = 12): SearchHit[] {
  const terms = query.toLowerCase().split(/\s+/).filter(Boolean);
  if (!terms.length) return [];
  const hits: SearchHit[] = [];
  for (const e of searchIndex()) {
    const title = e.page.title.toLowerCase();
    const heading = e.heading.toLowerCase();
    const text = e.text.toLowerCase();
    let score = 0;
    let ok = true;
    for (const t of terms) {
      const inH = heading.includes(t);
      const inT = title.includes(t);
      const inX = text.includes(t);
      if (!inH && !inT && !inX) {
        ok = false;
        break;
      }
      score += (inH ? 6 : 0) + (inT ? 3 : 0) + (inX ? 1 : 0);
      if (heading === t || heading.startsWith(`${t} `)) score += 4;
    }
    if (!ok) continue;
    if (!e.anchor) score += 1;
    hits.push({ ...e, score, snippet: snippet(e.text, terms[0]) });
  }
  hits.sort((a, b) => b.score - a.score);
  return hits.slice(0, limit);
}

function snippet(text: string, term: string): string {
  const i = text.toLowerCase().indexOf(term);
  if (i < 0) return text.slice(0, 140);
  const start = Math.max(0, i - 50);
  return (
    (start ? "…" : "") + text.slice(start, start + 150) + (start + 150 < text.length ? "…" : "")
  );
}
