import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render } from "@testing-library/react";
import type { ReactElement } from "react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { vi } from "vitest";

export type Handler = (url: string, init?: RequestInit) => unknown;

/** Route fetch calls by URL substring (first match wins). Returns the spy. */
export function mockFetch(routes: [string, unknown | Handler][]) {
  const spy = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    for (const [frag, body] of routes) {
      if (url.includes(frag)) {
        const data = typeof body === "function" ? (body as Handler)(url, init) : body;
        return new Response(JSON.stringify(data), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        });
      }
    }
    return new Response(JSON.stringify({ detail: `no mock for ${url}` }), { status: 404 });
  });
  vi.stubGlobal("fetch", spy);
  return spy;
}

export function renderPage(ui: ReactElement, { route = "/", path = "*" } = {}) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter initialEntries={[route]}>
        <Routes>
          <Route path={path} element={ui} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}
