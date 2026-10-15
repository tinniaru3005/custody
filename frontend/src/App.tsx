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

export default function App() {
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
