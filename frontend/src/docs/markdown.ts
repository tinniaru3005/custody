import { Marked, type Tokens } from "marked";
import { highlight } from "./highlight";
import { REPO_URL } from "./nav";

/** Screenshots and figures, bundled by Vite (hashed URLs under /assets). */
const IMAGES = import.meta.glob("./images/*.{webp,png,svg}", {
  eager: true,
  query: "?url",
  import: "default",
}) as Record<string, string>;
const IMAGE_BY_NAME: Record<string, string> = Object.fromEntries(
  Object.entries(IMAGES).map(([path, url]) => [path.split("/").pop()!, url]),
);

export function imageUrl(name: string): string | undefined {
  return IMAGE_BY_NAME[name.replace(/^\.?\/?(images\/)?/, "")];
}

export interface Heading {
  depth: number;
  text: string;
  id: string;
}

export interface RenderedDoc {
  html: string;
  headings: Heading[];
  title: string;
  /** image names referenced but not found (checked by the docs tests) */
  missingImages: string[];
}

const CALLOUTS: Record<string, string> = {
  NOTE: "Note",
  TIP: "Tip",
  WARNING: "Warning",
  SIMULATED: "Simulated in the demo",
  REAL: "Real, not simulated",
  LIMITATION: "Limitation",
};

export function escapeHtml(s: string): string {
  return s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

export function stripTags(html: string): string {
  return html
    .replace(/<[^>]+>/g, "")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'")
    .replace(/&amp;/g, "&");
}

export function slugify(text: string): string {
  return (
    stripTags(text)
      .toLowerCase()
      .replace(/[`'"’]/g, "")
      .replace(/[^a-z0-9]+/g, "-")
      .replace(/^-+|-+$/g, "") || "section"
  );
}

/** `repo:path/to/file#L10` → a GitHub link to the file on main. */
export function resolveHref(href: string): string {
  if (href.startsWith("repo:")) {
    const rest = href.slice(5);
    const isDir = rest.endsWith("/");
    return `${REPO_URL}/${isDir ? "tree" : "blob"}/main/${rest.replace(/\/$/, "")}`;
  }
  return href;
}

function isExternal(href: string): boolean {
  return /^https?:\/\//.test(href);
}

/** Render one Markdown page. Content is first-party (shipped with the app), so raw HTML
 * blocks (diagrams) are allowed. */
export function renderMarkdown(source: string): RenderedDoc {
  const headings: Heading[] = [];
  const used = new Map<string, number>();
  const missingImages: string[] = [];
  let title = "";

  const md = new Marked({ gfm: true });
  md.use({
    renderer: {
      heading(this: { parser: { parseInline: (t: Tokens.Generic[]) => string } }, tok) {
        const inner = this.parser.parseInline(tok.tokens);
        if (tok.depth === 1) {
          title = stripTags(inner);
          return `<h1>${inner}</h1>\n`;
        }
        let id = slugify(inner);
        const n = used.get(id) ?? 0;
        used.set(id, n + 1);
        if (n) id = `${id}-${n}`;
        headings.push({ depth: tok.depth, text: stripTags(inner), id });
        return (
          `<h${tok.depth} id="${id}"><a class="anchor" href="#${id}" aria-label="Link to this section">#</a>` +
          `${inner}</h${tok.depth}>\n`
        );
      },
      code(tok) {
        const info = (tok.lang ?? "").trim();
        const lang = info.split(/\s+/)[0] || "text";
        const titleMatch = info.match(/title="([^"]+)"/);
        const label = titleMatch ? titleMatch[1] : lang === "text" ? "" : lang;
        const body = highlight(tok.text, lang);
        return (
          `<div class="code-block" data-lang="${escapeHtml(lang)}">` +
          `<div class="code-head"><span class="code-label">${escapeHtml(label)}</span>` +
          `<button type="button" class="copy-btn" data-copy aria-label="Copy code">Copy</button></div>` +
          `<pre><code class="hljs language-${escapeHtml(lang)}">${body}</code></pre></div>\n`
        );
      },
      blockquote(this: { parser: { parse: (t: Tokens.Generic[]) => string } }, tok) {
        let inner = this.parser.parse(tok.tokens);
        const m = inner.match(/^<p>\[!([A-Z]+)\]\s*/);
        if (m && CALLOUTS[m[1]]) {
          const kind = m[1].toLowerCase();
          inner = inner.replace(m[0], "<p>");
          return (
            `<aside class="callout callout-${kind}" role="note">` +
            `<div class="callout-title">${CALLOUTS[m[1]]}</div>${inner}</aside>\n`
          );
        }
        return `<blockquote>${inner}</blockquote>\n`;
      },
      image(tok) {
        const url = imageUrl(tok.href);
        if (!url) {
          missingImages.push(tok.href);
          return `<span class="missing-image">[missing image: ${escapeHtml(tok.href)}]</span>`;
        }
        const caption = tok.title ?? "";
        return (
          `<figure class="shot"><button type="button" class="shot-zoom" data-zoom="${url}" ` +
          `aria-label="Enlarge screenshot: ${escapeHtml(tok.text)}">` +
          `<img src="${url}" alt="${escapeHtml(tok.text)}" loading="lazy" decoding="async"></button>` +
          (caption ? `<figcaption>${escapeHtml(caption)}</figcaption>` : "") +
          `</figure>`
        );
      },
      link(this: { parser: { parseInline: (t: Tokens.Generic[]) => string } }, tok) {
        const inner = this.parser.parseInline(tok.tokens);
        const href = resolveHref(tok.href);
        const t = tok.title ? ` title="${escapeHtml(tok.title)}"` : "";
        // repository links read as code references; other external links get a ↗ marker
        const cls = tok.href.startsWith("repo:") ? "repo" : "ext";
        if (isExternal(href))
          return `<a href="${escapeHtml(href)}"${t} target="_blank" rel="noopener noreferrer" class="${cls}">${inner}</a>`;
        return `<a href="${escapeHtml(href)}"${t}>${inner}</a>`;
      },
      table(this: { parser: { parseInline: (t: Tokens.Generic[]) => string } }, tok) {
        const cell = (c: Tokens.TableCell, tag: "th" | "td") => {
          const align = c.align ? ` style="text-align:${c.align}"` : "";
          return `<${tag}${align}>${this.parser.parseInline(c.tokens)}</${tag}>`;
        };
        const head = `<tr>${tok.header.map((c) => cell(c, "th")).join("")}</tr>`;
        const rows = tok.rows.map((r) => `<tr>${r.map((c) => cell(c, "td")).join("")}</tr>`);
        return (
          `<div class="table-wrap" tabindex="0"><table><thead>${head}</thead>` +
          `<tbody>${rows.join("")}</tbody></table></div>\n`
        );
      },
    },
  });
  const html = md.parse(source, { async: false }) as string;
  return { html, headings, title, missingImages };
}
