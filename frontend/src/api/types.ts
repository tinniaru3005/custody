// Typed mirror of the FastAPI response models (custody/console/views.py, custody/guard/models.py,
// custody/demo/attack.py, custody/console/service.py, custody/warden/models.py).

export type Verdict = "ALLOW" | "REQUIRE_HUMAN_APPROVAL" | "BLOCK";
export type CheckName =
  "integrity" | "confidentiality" | "lethal_trifecta" | "human_review" | "precedent";
export type ActionStatus =
  "proposed" | "pending_approval" | "approved" | "blocked" | "rejected" | "executed" | "failed";

export type NodeLabel =
  | "Source"
  | "Datum"
  | "Memory"
  | "Recall"
  | "Message"
  | "Typed"
  | "Action"
  | "Sink"
  | "Approval"
  | "Decision"
  | "Quarantine";

export type EdgeType =
  | "FROM"
  | "DERIVED_FROM"
  | "ARG"
  | "TO"
  | "ENDORSES"
  | "APPROVES"
  | "REJECTS"
  | "EVALUATES"
  | "QUARANTINES"
  | "VIA";

export interface GraphNode {
  id: string;
  label: NodeLabel;
  labels: string[];
  title: string;
  kind?: string | null;
  agent?: string | null;
  session_id?: string | null;
  preview?: string | null;
  created_at?: string | null;
  sim_time?: string | null;
  sim_day?: string | null;
  step?: number | null;
  trust?: string | null;
  sensitivity?: string | null;
  status?: string | null;
  verdict?: string | null;
  external?: boolean | null;
  flags: string[];
  metadata: Record<string, unknown>;
}

export interface GraphEdge {
  id: string;
  source: string;
  target: string;
  type: EdgeType;
  op?: string | null;
  attribution?: string | null;
  role?: string | null;
}

export interface GraphView {
  nodes: GraphNode[];
  edges: GraphEdge[];
  counts: Record<string, number>;
}

export interface AgentSummary {
  name: string;
  role: string;
  sessions: string[];
  data: number;
  memories: number;
  actions: number;
  allowed: number;
  approval: number;
  blocked: number;
  contaminated: boolean;
  last_seen?: string | null;
}

export interface ActionSummary {
  id: string;
  action_type: string;
  agent: string;
  session_id?: string | null;
  status: ActionStatus;
  created_at: string;
  sim_time?: string | null;
  destination?: string | null;
  sink_kind?: string | null;
  external: boolean;
  verdict?: Verdict | null;
  triggered: string[];
  latency_ms?: number | null;
  explanation?: string | null;
  decisions: number;
  metadata: Record<string, unknown>;
}

export interface MemorySummary {
  id: string;
  key?: string | null;
  agent?: string | null;
  session_id?: string | null;
  preview: string;
  created_at: string;
  sim_time?: string | null;
  in_quarantine: boolean;
  quarantine_id?: string | null;
  tainted: boolean;
}

export interface QuarantineSummary {
  id: string;
  memory_ids: string[];
  reason?: string | null;
  action_id?: string | null;
  incident_id?: string | null;
  created_at?: string | null;
}

export interface IncidentSummary {
  id: string;
  severity: "critical" | "high" | "medium" | "low";
  sources: string[];
  summary: string;
  memories: number;
  messages: number;
  actions: number;
  blocked: string[];
  executed_external: string[];
}

export interface Overview {
  tenant: string;
  empty: boolean;
  demo?: {
    id: string;
    created_at: string;
    blocked_action?: string;
    slack_action?: string;
    cleanup_request?: string;
  } | null;
  agents: AgentSummary[];
  actions: ActionSummary[];
  counts: Record<string, number>;
  incidents: IncidentSummary[];
  memories: MemorySummary[];
  quarantines: QuarantineSummary[];
  graph_counts: Record<string, number>;
}

// ------------------------------------------------------------------ Guard decision
export interface PathNode {
  id: string;
  labels: string[];
  kind?: string | null;
  agent?: string | null;
  session_id?: string | null;
  preview?: string | null;
  sensitivity?: string | null;
  endorsed: boolean;
  quarantined: boolean;
  trust?: string | null;
}

export interface PathEvidence {
  check: CheckName;
  arg_role: string;
  arg_datum_id: string;
  nodes: PathNode[];
  ops: string[];
  length: number;
  status: "violating" | "cleared" | "limited" | "info";
  cleared_by: string[];
  endorsed_datum_ids: string[];
  typed_datum_ids: string[];
  sessions: string[];
  agents: string[];
  text: string;
}

export interface CheckResult {
  name: CheckName;
  evaluated: boolean;
  violated: boolean;
  raw_violation: boolean;
  detail: string;
  paths: PathEvidence[];
  cleared_by_action_approval: string[];
  latency_ms: number;
  query?: string | null;
  search?: ProvenanceSearch | null; // complete search behind the verdict
  cleared_by_endorsement?: string[]; // secret-egress endorsements (Approval ids)
  precedents?: Precedent[]; // precedent check only
}

export interface Precedent {
  rejected_action_id: string;
  rejected_action_type: string;
  approval_id: string;
  approver: string;
  reason?: string | null;
  rejected_at?: string | null;
  sink_id: string;
  sink_destination?: string | null;
  secret_payload_datum_ids: string[];
  relationship: string;
}

export interface ChainNode {
  id: string;
  kind?: string | null;
  agent?: string | null;
  session_id?: string | null;
  preview?: string | null;
  trust?: string | null;
  op?: string | null;
}

export interface World {
  key: string;
  title: string;
  subtitle: string;
  history: string[];
  action_id: string;
  verdict: Verdict;
  triggered: string[];
  why: string;
  destination: string;
  destination_fingerprint: string;
  payload_fingerprint: string;
  provenance: ChainNode[];
  explanation: string;
  certificate?: ProvenanceCertificate | null;
  latency_ms: number;
}

export interface WorldsRun {
  id: string;
  request: string;
  destination: string;
  identical_destination: boolean;
  identical_payload: boolean;
  message: string;
  simulation: string[];
  worlds: World[];
}

export interface ReadjudicatedAction {
  action_id: string;
  action_type: string;
  agent: string;
  status: string;
  executed: boolean;
  original_verdict?: Verdict | null;
  original_decision_id?: string | null;
  original_evaluated_at?: string | null;
  current_verdict: Verdict;
  current_triggered: string[];
  current_explanation: string;
  current_path?: string | null;
  transition: string;
  changed: boolean;
}

export interface ReadjudicationReport {
  id: string;
  source_id: string;
  trust_before: string;
  trust_after: string;
  revoked_by: string;
  reason?: string | null;
  revoked_at: string;
  graph_version_before: string;
  graph_version_after: string;
  downstream_datums: number;
  memories: string[];
  messages: string[];
  actions: ReadjudicatedAction[];
  summary: Record<string, number>;
  known_then: string;
  known_now: string;
}

export interface Chokepoint {
  id: string;
  labels: string[];
  kind?: string | null;
  agent?: string | null;
  session_id?: string | null;
  paths_through?: number | null;
  path_share?: number | null;
  verified: boolean;
  trivial: boolean;
  quarantinable: boolean;
  explanation: string;
}

export interface InfluencePathStep {
  id: string;
  label: string;
  kind?: string | null;
  agent?: string | null;
  session_id?: string | null;
  trust?: string | null;
  op?: string | null;
}

export interface InfluenceEdge {
  id: string;
  source: string;
  target: string;
  via?: string | null;
  via_label?: string | null;
  via_preview?: string | null;
  kind: "entry" | "memory" | "message" | "direct";
  edges: number;
  followed: boolean;
  tainted: boolean;
  sessions: string[];
  path: InfluencePathStep[];
}

export interface InfluenceView {
  participants: { id: string; label: string; type: "agent" | "source"; tainted: boolean }[];
  influences: InfluenceEdge[];
  summary: string;
}

export interface ChokepointResult {
  action_id: string;
  dangerous: boolean;
  untrusted_sources: string[];
  total_paths?: number | null;
  candidates_checked: number;
  chokepoints: Chokepoint[];
  recommended?: string | null;
  summary: string;
  method: string;
}

export interface ProvenanceSearch {
  outcome: "PATH_FOUND" | "NO_PATH" | "INDETERMINATE";
  path_found: boolean;
  search_complete: boolean;
  termination_reason: string;
  max_depth_reached: boolean;
  depth_explored: number;
  nodes_visited: number;
  latency_ms: number;
}

export interface SourceInfo {
  id: string;
  kind: string;
  trust: string;
  reached_from: string[];
}

export interface SinkInfo {
  id?: string | null;
  kind?: string | null;
  destination?: string | null;
  workspace?: string | null;
  declared_external?: boolean | null;
  external: boolean;
  zone: string;
  reason: string;
  bound?: boolean | null;
}

export interface ApprovalOption {
  available: boolean;
  reason: string;
  endorse_datum_ids: string[];
  approve_checks: string[];
}

export interface GuardDecision {
  id: string;
  action_id: string;
  action_type: string;
  agent: string;
  action_status: ActionStatus;
  decision: Verdict;
  triggered_checks: CheckName[];
  explanation: string;
  checks: Record<CheckName, CheckResult>;
  paths: PathEvidence[];
  sources: SourceInfo[];
  sink: SinkInfo;
  approval: ApprovalOption;
  latency_ms: Record<string, number>;
  policy: string;
  evaluated_at: string;
  deterministic: boolean;
  search_complete?: boolean;
  indeterminate_checks?: CheckName[];
  certificate?: ProvenanceCertificate | null;
  certificate_unavailable?: string | null;
  /** distinct untrusted roots + route independence (explanation only) */
  contamination?: ContaminationReport | null;
}

export interface RootRoute {
  source_id: string;
  source_kind?: string | null;
  source_label?: string | null;
  entry_datum_id: string;
  hops: number;
  path: PathEvidence;
}

export interface ContaminationReport {
  root_count: number;
  roots_complete: boolean;
  roots: RootRoute[];
  /** independent | converging | direct | unverified */
  independence: string;
  independent_routes: number;
  method?: string | null;
  shared_datum_id?: string | null;
  extra_routes: PathEvidence[];
  detail: string;
  checks_run: number;
  latency_ms: number;
  note: string;
}

export interface RootSource {
  id: string;
  kind?: string | null;
  trust?: string | null;
  datum_ids: string[];
  min_depth: number;
  status: "followed" | "context_only" | "cleared";
  note: string;
}

/** Evidence behind an ALLOW: the negative claim, scoped and tied to a graph version. */
export interface ProvenanceCertificate {
  id: string;
  action_id: string;
  decision_id: string;
  issued_at: string;
  claim: string;
  scope: string;
  untrusted_influence: "NONE_FOUND";
  traversal_complete: boolean;
  frontier_exhausted: boolean;
  termination_reason: string;
  root_sources_checked: number;
  root_sources: RootSource[];
  untrusted_roots_not_followed: number;
  max_depth_reached: number;
  nodes_examined: number;
  relationships_examined: number;
  derived_from_edges_examined: number;
  context_edges_examined: number;
  context_provenance_included: boolean;
  guard_followed_nodes: number;
  graph: string;
  graph_version: number;
  graph_version_label: string;
  ancestry_digest: string;
  payload: string;
  guard_latency_ms: number;
  certificate_latency_ms: number;
  /** FULL_CONTEXT only if every model output in the ancestry linked its whole context */
  provenance_coverage?: "FULL_CONTEXT" | "REDUCED";
  strength?: "STRONG" | "DOWNGRADED";
  reduced_provenance_count?: number;
  reduced_provenance?: { datum_id: string; kind?: string | null; coverage?: string | null }[];
  trust_labels_note?: string;
  /** deterministic fingerprint of the decision state (not a proof) */
  certificate_id?: string;
  certificate_id_inputs?: string[];
}

export interface ChainCard {
  role: string;
  id: string;
  label: string;
  title: string;
  op?: string;
  agent?: string | null;
  session_id?: string | null;
  kind?: string | null;
  trust?: string | null;
  sensitivity?: string | null;
  endorsed?: boolean;
  external?: boolean;
  detail?: string;
  verdict?: Verdict;
  path_status?: string;
  path_length?: number;
  path_check?: string;
}

export interface ApprovalRecordView {
  id: string;
  approver: string;
  approver_kind?: string;
  reason?: string | null;
  verdict?: string;
  created_at: string;
  relation: "APPROVES" | "REJECTS" | "ENDORSES";
  datum_id?: string;
}

export interface DecisionRecord {
  id: string;
  action_id: string;
  decision: Verdict;
  triggered: string[];
  explanation: string;
  latency_ms: number;
  policy: string;
  created_at: string;
}

export interface ActionExplain {
  action: ActionSummary;
  decision: GuardDecision;
  history: DecisionRecord[];
  approvals: ApprovalRecordView[];
  chain: ChainCard[];
}

export interface ApprovalItem {
  explain: ActionExplain;
  can_approve: boolean;
  why: string;
}

export interface ApprovalQueue {
  pending: ApprovalItem[];
  blocked: ApprovalItem[];
  resolved: ActionSummary[];
}

export interface Metrics {
  focus_action?: string | null;
  guard_latency_ms?: number | null;
  guard_latency_breakdown: Record<string, number>;
  guard_latency_samples: number[];
  guard_latency_p50?: number | null;
  guard_latency_max?: number | null;
  path_length?: number | null;
  sessions_crossed: string[];
  agents_crossed: string[];
  affected_memories: number;
  affected_agents: string[];
  affected_actions: number;
  affected_messages: number;
  blocked_actions: number;
  decisions_recorded: number;
  deterministic_runs: number;
  deterministic_identical: boolean;
  graph_nodes: number;
  graph_edges: number;
  queries: { name: string; purpose: string; pattern: string }[];
}

// ------------------------------------------------------------------ demo + Warden
export type StepTone = "info" | "allow" | "approval" | "block" | "warning" | "trace";

export interface DemoStep {
  n: number;
  key: string;
  title: string;
  actor: string;
  day: string;
  sim_time: string;
  narrative: string;
  simulated?: string[]; // simulated systems this step touches
  node_ids: string[];
  action_id?: string | null;
  verdict?: Verdict | null;
  status?: ActionStatus | null;
  tone: StepTone;
}

export interface DemoRun {
  id: string;
  tenant: string;
  created_at: string;
  scenario?: "primary" | "extended";
  simulation?: string[]; // what is simulated (always shown with the demo)
  steps: DemoStep[];
  ids: Record<string, string>;
  blocked_decision: GuardDecision;
  slack_decision: GuardDecision;
  outbox: { action_id: string; tool: string; destination: string; sink_kind: string }[];
  cleanup_request: string;
  /** scripted simulation, or the deterministic replay of a recorded LLM run */
  mode?: "scripted" | "recorded";
  recording?: DemoRecording | null;
}

export interface DemoRecording {
  label: string; // "Recorded real LLM execution — deterministic replay" when real_llm
  real_llm: boolean;
  model: string;
  recorded_at: string;
  llm_calls: number; // model calls in the recording
  llm_calls_made: number; // model calls made by this replay (0)
}

export type PlannerName = "auto" | "playbook" | "anthropic";

export interface WardenStep {
  n: number;
  tool: string;
  arguments: Record<string, unknown>;
  is_error: boolean;
  result: unknown;
}

export interface PendingApproval {
  action_id: string;
  recipient: string;
  verdict: string;
  status: string;
  how_to_approve: string;
}

export interface WardenRun {
  id: string;
  created_at: string;
  request: string;
  operator: string;
  planner: string;
  final_text: string;
  steps: WardenStep[];
  tools_used: string[];
  quarantined_memory_ids: string[];
  quarantine_verdicts: string[];
  external_executed_actions: string[];
  drafts: string[];
  pending_approvals: PendingApproval[];
}

export interface SendDisclosureResult {
  action_id: string;
  sent: boolean;
  verdict: string;
  status: string;
  destination?: string | null;
  payload_fingerprint?: string | null;
  detail: string;
}

export interface DatumRecord {
  id: string;
  kind: string;
  labels: string[];
  value?: string | null;
  preview: string;
  sensitivity: string;
  agent?: string | null;
  session_id?: string | null;
  metadata: Record<string, unknown>;
}

export interface Health {
  status: "ok" | "degraded";
  falkordb: boolean;
  version: string;
  public_demo?: boolean; // read-only public demo: one tenant, reset only
  demo_tenant?: string;
}

// Warden tool results (subset of fields the UI renders)
export interface NodeRef {
  id: string;
  labels: string[];
  kind?: string | null;
  agent?: string | null;
  session_id?: string | null;
  preview?: string | null;
  in_quarantine: boolean;
  key?: string | null;
  depth?: number | null;
  influence?: "direct" | "context_only" | null;
}

export interface ActionView {
  id: string;
  action_type: string;
  agent: string;
  status: string;
  external: boolean;
  executed: boolean;
  influence?: "direct" | "context_only" | null;
  latest_decision?: string | null;
  sink?: { destination?: string | null; zone: string } | null;
}
