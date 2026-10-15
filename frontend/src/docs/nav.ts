/** Documentation structure. Each page is a Markdown file in ./content/<slug>.md; the
 * overview page is served at /docs and every other page at /docs/<slug>. */

export const REPO_URL = "https://github.com/tinniaru3005/custody";
export const DOCS_BASE = "/docs";

export interface DocPage {
  slug: string;
  title: string;
  /** one line for search results and the overview page */
  summary: string;
}

export interface DocSection {
  title: string;
  pages: DocPage[];
}

export const SECTIONS: DocSection[] = [
  {
    title: "Getting started",
    pages: [
      {
        slug: "overview",
        title: "Overview",
        summary: "What Custody is, what it decides, and what the demo simulates",
      },
      {
        slug: "quickstart",
        title: "Quickstart",
        summary: "Run the API, the console and the attack demo locally",
      },
      {
        slug: "installation",
        title: "Installation",
        summary: "Requirements, database options and verifying a setup",
      },
    ],
  },
  {
    title: "Concepts",
    pages: [
      {
        slug: "architecture",
        title: "Architecture",
        summary: "Components, request flow and the repository layout",
      },
      {
        slug: "provenance-graph",
        title: "Provenance graph",
        summary: "Nodes, relationships, invariants and the recording rule",
      },
      {
        slug: "guard",
        title: "Guard",
        summary: "Checks, verdicts, complete search, certificates and approvals",
      },
      {
        slug: "warden",
        title: "Warden",
        summary: "Incident investigation, quarantine and disclosures",
      },
      {
        slug: "mcp",
        title: "MCP integration",
        summary: "The Warden MCP server, its tools and client setup",
      },
    ],
  },
  {
    title: "Guides",
    pages: [
      {
        slug: "console",
        title: "Console tour",
        summary: "Every page of the web console, with screenshots",
      },
      {
        slug: "demos",
        title: "Demo scenarios",
        summary: "The primary attack, three worlds and the extended scenario",
      },
      {
        slug: "integrating",
        title: "Recording your own agents",
        summary: "Record provenance over HTTP or with the Python runtime",
      },
    ],
  },
  {
    title: "Reference",
    pages: [
      {
        slug: "api-reference",
        title: "HTTP API",
        summary: "Every endpoint, request body and status code",
      },
      {
        slug: "configuration",
        title: "Configuration",
        summary: "Environment variables and Guard policy",
      },
      {
        slug: "cli",
        title: "Commands and scripts",
        summary: "Warden CLI, demo scripts and make targets",
      },
      {
        slug: "benchmarks",
        title: "Benchmarks",
        summary: "What the committed benchmark run measured, and what it cannot show",
      },
    ],
  },
  {
    title: "Operations",
    pages: [
      {
        slug: "deployment",
        title: "Deployment",
        summary: "Docker, Render, public-demo mode and split hosting",
      },
      {
        slug: "security",
        title: "Security model",
        summary: "Threat model, assumptions and known limitations",
      },
      {
        slug: "troubleshooting",
        title: "Troubleshooting",
        summary: "Common errors and how to fix them",
      },
    ],
  },
];

export const PAGES: DocPage[] = SECTIONS.flatMap((s) => s.pages);

export function pagePath(slug: string): string {
  return slug === "overview" ? DOCS_BASE : `${DOCS_BASE}/${slug}`;
}

export function sectionOf(slug: string): DocSection | undefined {
  return SECTIONS.find((s) => s.pages.some((p) => p.slug === slug));
}
