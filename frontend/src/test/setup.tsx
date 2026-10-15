import "@testing-library/jest-dom/vitest";
import { cleanup } from "@testing-library/react";
import { afterEach, vi } from "vitest";

// The canvas force graph cannot run in jsdom; tests render a list of the visible node ids.
vi.mock("react-force-graph-2d", () => ({
  default: (props: { graphData: { nodes: { id: string }[] } }) => (
    <ul data-testid="force-graph-mock">
      {props.graphData.nodes.map((n) => (
        <li key={n.id}>{n.id}</li>
      ))}
    </ul>
  ),
}));

class RO {
  observe() {}
  disconnect() {}
  unobserve() {}
}
vi.stubGlobal("ResizeObserver", RO);

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
  vi.stubGlobal("ResizeObserver", RO);
});
