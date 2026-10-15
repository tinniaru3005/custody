import { lazy, Suspense } from "react";
import { Route, Routes } from "react-router-dom";
import { Layout } from "./components/Layout";
import { ApprovalsPage } from "./pages/ApprovalsPage";
import { DashboardPage } from "./pages/DashboardPage";
import { DemoPage } from "./pages/DemoPage";
import { GraphPage } from "./pages/GraphPage";
import { GuardPage } from "./pages/GuardPage";
import { MetricsPage } from "./pages/MetricsPage";
import { WardenPage } from "./pages/WardenPage";
import { WorldsPage } from "./pages/WorldsPage";

// The documentation site (/docs) is its own layout and bundle, loaded on first visit.
const DocsApp = lazy(() => import("./docs/DocsApp"));

function Console() {
  return (
    <Layout>
      <Routes>
        <Route path="/" element={<DashboardPage />} />
        <Route path="/demo" element={<DemoPage />} />
        <Route path="/worlds" element={<WorldsPage />} />
        <Route path="/graph" element={<GraphPage />} />
        <Route path="/guard" element={<GuardPage />} />
        <Route path="/guard/:actionId" element={<GuardPage />} />
        <Route path="/approvals" element={<ApprovalsPage />} />
        <Route path="/warden" element={<WardenPage />} />
        <Route path="/metrics" element={<MetricsPage />} />
        <Route path="*" element={<p className="page">Page not found.</p>} />
      </Routes>
    </Layout>
  );
}

export default function App() {
  return (
    <Routes>
      <Route
        path="/docs/*"
        element={
          <Suspense fallback={<p className="page muted">Loading documentation…</p>}>
            <DocsApp />
          </Suspense>
        }
      />
      <Route path="*" element={<Console />} />
    </Routes>
  );
}
