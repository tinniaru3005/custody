import type {
  ActionExplain,
  ActionSummary,
  ApprovalQueue,
  DatumRecord,
  DemoRun,
  GraphView,
  GuardDecision,
  Health,
  Metrics,
  Overview,
  PlannerName,
  SendDisclosureResult,
  WardenRun,
  WorldsRun,
  InfluenceView,
  ChokepointResult,
  ReadjudicationReport,
} from "./types";

export const API_BASE: string = import.meta.env.VITE_API_BASE ?? "/api";
export const TENANT: string = import.meta.env.VITE_TENANT ?? "acme";

export class ApiError extends Error {
  readonly status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
    this.name = "ApiError";
  }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  let res: Response;
  try {
    res = await fetch(`${API_BASE}${path}`, {
      ...init,
      headers: { "Content-Type": "application/json", ...(init?.headers ?? {}) },
    });
  } catch {
    throw new ApiError(0, "Cannot reach the Custody API. Is the backend running?");
  }
  if (!res.ok) {
    let detail = res.statusText;
    try {
      const body = await res.json();
      detail = typeof body.detail === "string" ? body.detail : JSON.stringify(body.detail);
    } catch {
      /* not JSON */
    }
    throw new ApiError(res.status, detail || `HTTP ${res.status}`);
  }
  if (res.status === 204) return undefined as T;
  return (await res.json()) as T;
}

const t = (tenant: string) => `/tenants/${encodeURIComponent(tenant)}`;
const c = (tenant: string) => `${t(tenant)}/console`;
const post = (body?: unknown): RequestInit => ({
  method: "POST",
  body: body === undefined ? undefined : JSON.stringify(body),
});

export const api = {
  health: () => request<Health>("/health"),
  overview: (tenant = TENANT) => request<Overview>(`${c(tenant)}/overview`),
  graph: (tenant = TENANT, includeDecisions = false) =>
    request<GraphView>(`${c(tenant)}/graph?include_decisions=${includeDecisions}`),
  actions: (tenant = TENANT) => request<ActionSummary[]>(`${c(tenant)}/actions`),
  explain: (actionId: string, tenant = TENANT) =>
    request<ActionExplain>(`${c(tenant)}/actions/${encodeURIComponent(actionId)}/explain`),
  approvals: (tenant = TENANT) => request<ApprovalQueue>(`${c(tenant)}/approvals`),
  metrics: (tenant = TENANT) => request<Metrics>(`${c(tenant)}/metrics`),
  demo: (tenant = TENANT) => request<DemoRun | null>(`${c(tenant)}/demo`),
  wardenRun: (tenant = TENANT) => request<WardenRun | null>(`${c(tenant)}/warden`),
  influence: (tenant = TENANT) => request<InfluenceView>(`${c(tenant)}/influence`),
  worlds: (tenant = TENANT) => request<WorldsRun | null>(`${c(tenant)}/worlds`),
  buildWorlds: (tenant = TENANT) => request<WorldsRun>(`${c(tenant)}/worlds`, post()),
  chokepoints: (actionId: string, tenant = TENANT) =>
    request<ChokepointResult>(`${c(tenant)}/actions/${encodeURIComponent(actionId)}/chokepoints`),
  readjudications: (tenant = TENANT) =>
    request<ReadjudicationReport[]>(`${t(tenant)}/guard/readjudications`),
  datum: (id: string, tenant = TENANT) =>
    request<DatumRecord>(`${t(tenant)}/data/${encodeURIComponent(id)}`),

  runAttack: (tenant = TENANT) => request<DemoRun>(`${c(tenant)}/demo/attack`, post()),
  reset: (tenant = TENANT) => request<void>(`${c(tenant)}/demo/reset`, post()),
  investigate: (request_: string, planner: PlannerName = "auto", tenant = TENANT) =>
    request<WardenRun>(`${c(tenant)}/warden/investigate`, post({ request: request_, planner })),
  approve: (actionId: string, approver: string, reason?: string, tenant = TENANT) =>
    request<GuardDecision>(
      `${t(tenant)}/guard/actions/${encodeURIComponent(actionId)}/approve`,
      post({ approver, reason: reason || null }),
    ),
  reject: (actionId: string, approver: string, reason?: string, tenant = TENANT) =>
    request<ActionSummary>(
      `${t(tenant)}/guard/actions/${encodeURIComponent(actionId)}/reject`,
      post({ approver, reason: reason || null }),
    ),
  sendDisclosure: (actionId: string, tenant = TENANT) =>
    request<SendDisclosureResult>(
      `${c(tenant)}/warden/disclosures/${encodeURIComponent(actionId)}/send`,
      post(),
    ),
};
