/// <reference types="node" />
import { fireEvent, render, screen, within } from "@testing-library/react";
import { existsSync, readdirSync } from "node:fs";
import { resolve } from "node:path";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { loadPage, rawPage, search } from "./content";
import DocsApp from "./DocsApp";
import { renderMarkdown, resolveHref } from "./markdown";
import { PAGES, pagePath } from "./nav";

const REPO_ROOT = resolve(__dirname, "../../..");
const IMAGES_DIR = resolve(__dirname, "images");

function renderDocs(route: string) {
  return render(
    <MemoryRouter initialEntries={[route]}>
      <Routes>
        <Route path="/docs/*" element={<DocsApp />} />
      </Routes>
    </MemoryRouter>,
  );
}

function linksOf(html: string): string[] {
  return [...html.matchAll(/<a href="([^"]+)"/g)].map((m) => m[1].replace(/&amp;/g, "&"));
}

describe("documentation content", () => {
  it("has a Markdown file with a title for every page in the navigation", () => {
    for (const p of PAGES) {
      expect(rawPage(p.slug), p.slug).toBeDefined();
      expect(loadPage(p.slug)!.title, p.slug).not.toBe("");
    }
  });

  it("references only screenshots that exist, and ships none that are unused", () => {
    const used = new Set<string>();
    for (const p of PAGES) {
      const raw = rawPage(p.slug)!;
      expect(renderMarkdown(raw).missingImages, p.slug).toEqual([]);
      for (const m of raw.matchAll(/!\[[^\]]*\]\(([^)\s]+)/g)) used.add(m[1]);
    }
    const files = readdirSync(IMAGES_DIR).filter((f) => !f.startsWith("."));
    expect(files.filter((f) => !used.has(f))).toEqual([]);
  });

  it("has no broken internal links or anchors", () => {
    const anchors = new Map(
      PAGES.map((p) => [p.slug, new Set(loadPage(p.slug)!.headings.map((h) => h.id))]),
    );
    const broken: string[] = [];
    for (const p of PAGES) {
      for (const href of linksOf(loadPage(p.slug)!.html)) {
        if (/^https?:/.test(href) || href.startsWith("mailto:")) continue;
        const [path, hash] = href.split("#");
        if (!path) {
          if (hash && !anchors.get(p.slug)!.has(hash)) broken.push(`${p.slug}: ${href}`);
          continue;
        }
        if (path === "/") continue;
        const m = path.match(/^\/docs(?:\/([a-z0-9-]+))?\/?$/);
        const slug = m ? (m[1] ?? "overview") : null;
        if (!slug || !anchors.has(slug)) broken.push(`${p.slug}: ${href}`);
        else if (hash && !anchors.get(slug)!.has(hash)) broken.push(`${p.slug}: ${href}`);
      }
    }
    expect(broken).toEqual([]);
  });

  it("links only to repository files that exist", () => {
    const missing: string[] = [];
    for (const p of PAGES) {
      for (const m of rawPage(p.slug)!.matchAll(/\]\(repo:([^)#\s]+)/g)) {
        if (!existsSync(resolve(REPO_ROOT, m[1]))) missing.push(`${p.slug}: ${m[1]}`);
      }
    }
    expect(missing).toEqual([]);
    expect(resolveHref("repo:custody/guard/")).toMatch(/\/tree\/main\/custody\/guard$/);
    expect(resolveHref("repo:Dockerfile")).toMatch(/\/blob\/main\/Dockerfile$/);
  });

  it("renders callouts, code blocks with copy buttons and captioned screenshots", () => {
    const doc = renderMarkdown(
      '# T\n\n> [!SIMULATED]\n> Fake.\n\n```bash\necho hi\n```\n\n![Alt](dashboard.webp "Caption")\n',
    );
    expect(doc.html).toContain('class="callout callout-simulated"');
    expect(doc.html).toContain("data-copy");
    expect(doc.html).toContain('<span class="hljs-built_in">echo</span>');
    expect(doc.html).toContain("<figcaption>Caption</figcaption>");
    expect(doc.html).toContain('loading="lazy"');
  });
});

describe("documentation search", () => {
  it("finds sections by heading and by text", () => {
    const hits = search("lethal trifecta");
    expect(hits.length).toBeGreaterThan(0);
    expect(hits.some((h) => h.page.slug === "guard")).toBe(true);
    expect(search("CUSTODY_PUBLIC_DEMO").some((h) => h.page.slug === "configuration")).toBe(true);
    expect(search("zzzz-not-in-the-docs")).toEqual([]);
  });
});

describe("DocsApp", () => {
  it("renders a page with navigation, table of contents and copy buttons", () => {
    renderDocs("/docs/guard");
    expect(screen.getByRole("heading", { level: 1, name: "Guard" })).toBeInTheDocument();
    const nav = screen.getByRole("complementary", { name: "Documentation" });
    expect(within(nav).getByRole("link", { name: "Guard" })).toHaveClass("active");
    const toc = screen.getByRole("complementary", { name: "On this page" });
    expect(within(toc).getByRole("link", { name: "Checks" })).toBeInTheDocument();
    expect(screen.getAllByRole("button", { name: "Copy code" }).length).toBeGreaterThan(0);
    expect(document.title).toBe("Guard · Custody docs");
  });

  it("serves the overview at /docs and a not-found page for unknown slugs", () => {
    renderDocs("/docs");
    expect(
      screen.getByRole("heading", { level: 1, name: "Custody documentation" }),
    ).toBeInTheDocument();
  });

  it("shows a not-found page for an unknown slug", () => {
    renderDocs("/docs/nope");
    expect(screen.getByRole("heading", { level: 1, name: "Page not found" })).toBeInTheDocument();
  });

  it("navigates with the pager and opens search from the keyboard", () => {
    renderDocs(pagePath("quickstart"));
    fireEvent.click(screen.getByRole("link", { name: /Next\s*Installation/ }));
    expect(screen.getByRole("heading", { level: 1, name: "Installation" })).toBeInTheDocument();
    fireEvent.keyDown(window, { key: "k", ctrlKey: true });
    const input = screen.getByRole("textbox", { name: "Search query" });
    fireEvent.change(input, { target: { value: "quarantine" } });
    expect(screen.getAllByRole("option").length).toBeGreaterThan(0);
  });

  it("toggles the theme", () => {
    const { container } = renderDocs("/docs");
    const root = container.querySelector(".docs")!;
    const before = root.getAttribute("data-theme");
    fireEvent.click(screen.getByRole("button", { name: /Switch to (light|dark) theme/ }));
    expect(root.getAttribute("data-theme")).not.toBe(before);
  });
});
