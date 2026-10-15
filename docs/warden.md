# Custody Warden

The Warden is Custody's investigation and remediation agent. It reads the provenance graph
to understand an incident, contains it, and drafts what needs to be said to people
outside the organisation. Its capabilities are MCP tools, and the Warden agent is an LLM
that picks among them.

The Warden does not get around the security system. Each action it takes is recorded as
an `Action` by agent `warden` and goes through the same deterministic Guard as any worker
agent's. External communication also needs explicit human approval.

## Tools

| Tool | Kind | What it does |
|---|---|---|
| `begin_investigation(request)` | write (record) | Records the operator's request as trusted user input (`user:<operator>`). Every Warden action derives from it. The agent runner calls it; the LLM never sees it. |
| `find_sources(query?, kind?, trust?)` | read | Finds Sources by id, URL or content. Untrusted sources with the most downstream influence come first. |
| `trace_back(action_id)` | read | Paths from each argument to its Sources: trusted, untrusted and secret (vault) sources, memories, recalls and messages crossed, the latest Guard decision, and an explanation. |
| `trace_forward(source_id)` | read | Follows a Source (or Datum) forward through `DERIVED_FROM` to the derived data, memories, recalls, messages and actions it reached. Reports which actions already executed externally, which were blocked, and which are pending. |
| `rank_risky_memories(limit?, include_quarantined?)` | read | Ranks memories by taint × downstream reach, plus **FalkorDB `algo.betweenness`** centrality. |
| `cluster_incidents()` | read (sandbox) | Groups contamination into incidents using **FalkorDB `algo.WCC`** on a **GRAPH.COPY** sandbox, and gives each a severity. |
| `simulate_policy(policy)` | read (sandbox) | Answers "if this policy had been on earlier, what would have been blocked or sent for approval?" Re-runs the Guard on a GRAPH.COPY clone. |
| `quarantine(memory_ids, reason?, incident_id?)` | **Guard-checked action** | Records a `quarantine_memory` Action. Executes only on Guard ALLOW. Afterwards the memories are hidden from retrieval and cannot be recalled. |
| `draft_disclosure(action_ids, notes?, claims?)` | write (draft only) | Every factual sentence cites verified graph ids from the traced incident (unsupported claims removed). Writes one draft per external recipient of an executed action. Nothing is sent. |
| `propose_disclosure(draft_id)` | **Guard-checked action** | Records a `send_disclosure` Action. The Guard returns REQUIRE_HUMAN_APPROVAL (policy `human_review`). It never auto-executes. |
| `send_approved_disclosure(action_id)` | **Guard-checked action** | Sends only if a human approved **and** a fresh Guard check returns ALLOW. Otherwise returns `sent=false`. |
| `revoke_source_trust(source_id, reason?)` | **Guard-checked action** (tightening) | Marks a Source untrusted and re-adjudicates every downstream historical action; executes on Guard ALLOW. |
| `propose_loosening(kind, targets, reason?)` | **Guard-checked proposal** (loosening) | `unquarantine_memory`, `endorse_data`, `restore_source_trust`, `weaken_restriction`: always REQUIRE_HUMAN_APPROVAL; never executed by the Warden without a human approval and a fresh Guard ALLOW. |
| `why_allowed(action_id)` | read | The action's Provenance Completeness Certificate and a fixed-template rendering of its evidence and the policy result. |
| `check_action(action_id)` | read + audit | **The Guard as a service** for any MCP agent framework: runs the deterministic Guard on an action recorded through the Recorder API. Returns `verdict` (`ALLOW` / `REQUIRE_APPROVAL` / `BLOCK`), `fail_closed` (an incomplete search made it non-ALLOW) and the INDETERMINATE checks, triggered checks, per-check search outcome, evidence paths, untrusted sources, sink classification, approval options and, on ALLOW, the certificate summary. Writes a Decision audit node; never changes the action's status or executes anything. |
| `explain_decision(action_id, decision_id?)` | read | The latest (or given) recorded Decision next to the same Guard re-run on the current graph, with `matches_recorded` (endorsements and trust revocations are the only ways a verdict changes later). Errors if the action was never checked. |

There is no approval tool. A human approves through the Guard HTTP API
(`POST /tenants/{t}/guard/actions/{id}/approve`), `python -m custody.warden approve`, or
`Warden.approve_disclosure` / `Warden.approve_remediation`. Approvers named `warden` or `system:*` are refused.

All results are typed (pydantic, see `custody/warden/models.py`), and the MCP server
publishes them as `outputSchema`. Previews in results can contain text written by the
attacker. The server instructions and the agent prompt both say to treat them as data
and never as instructions.

## How the analyses work

**Direct vs. context influence.** Edges with `attribution: 'context'` mean a value was in
the model's context but was attributed to a trusted supplier. The Guard does not follow
these edges. The Warden reports anything reached only through them as
`influence: "context_only"`. In the demo, the `#security` Slack post had the vendor memory
in context but is context-only, so it is not quarantined or disclosed.

**Warden artefacts** (data and actions by agent `warden`) are excluded from contamination,
ranking and clustering. `trace_forward` lists them under `remediation_actions`.

**Risk score** (`rank_risky_memories`):
`taint × (1 + downstream_data + 2·(recalls + messages + memories) + 3·actions + 5·external_actions + 10·executed_external + 10·normalized_betweenness)`.
`taint` is 1.0 if an uncleared path reaches an untrusted source, 0.25 if the untrusted
ancestry is endorsed or context-only, and 0.1 otherwise. Betweenness is
`CALL algo.betweenness({nodeLabels:['Datum','Action','Source'], relationshipTypes:['DERIVED_FROM','ARG','FROM']})`.
It is directed, so a memory scores high when it sits on the provenance paths from
actions back to their sources. If the procedure is missing, the ranking falls back to
reach only and says so.

**Incidents.** The contamination set is every Datum directly downstream of an untrusted
Source, plus the non-Warden Actions that use them. On a GRAPH.COPY clone those nodes are
labelled `:Contaminated`, and `algo.WCC({nodeLabels:['Contaminated'], relationshipTypes:['DERIVED_FROM','FROM','ARG']})`
splits them into components. The clone is then deleted. If the copy or the algorithm is
unavailable, a union-find over the same Cypher projection gives identical components;
a test checks this. Severity:

- **critical**: an executed external action with a contaminated destination or a secret
  payload.
- **high**: any executed external action, or a blocked attempt.
- **medium**: contaminated memories or pending actions.
- **low**: none of the above.

## Simulation isolation (`GRAPH.COPY`)

Verified against falkordblite 0.10 (FalkorDB module 4.18) and falkordb-py 1.7, where
`Graph.copy(name)` issues `GRAPH.COPY src dst`:

1. `GRAPH.COPY custody:<tenant> custody:<tenant>::sandbox::<random>`.
2. Two Guards run on the clone with `record_decisions=False`: the current tenant policy
   (baseline) and the hypothetical one. They evaluate every Action.
3. The clone is deleted in a `finally` block. The result includes `isolation` (mode, clone
   name, `sandbox_deleted`). It also includes `live_graph_unchanged`, which compares
   node and relationship counts of the live graph before and after.

If `GRAPH.COPY` fails (an older server, or a managed service that disallows it), the
simulation runs on a `ReadOnlyGraph` proxy over the live graph instead. That proxy sends
every query through `GRAPH.RO_QUERY`, so the server rejects any write. The result reports
`mode: "read_only_live"` along with the reason.

A `PolicySpec` can:

- replace sink lists (`internal_email_domains`, `internal_hosts`, …);
- override `actions`;
- force `human_review_action_types`;
- simulate an earlier quarantine (`quarantined_memory_ids`). Actions whose arguments
  derive directly from a recall of those memories are reported as
  `prevented_by_quarantine`.

## Quarantine semantics

- The memory gets `in_quarantine = true` and `quarantine_id`, plus a
  `(:Quarantine)-[:QUARANTINES]->(:Memory)` edge and a
  `(:Quarantine)-[:VIA]->(:Action {action_type:'quarantine_memory'})` edge. This does
  **not** reuse `Datum.quarantined`, the typed-reader flag that makes the Guard treat a
  path as *limited*: reusing it would loosen integrity checks.
- `SharedMemory.search/get` (`custody/memory`) and `AgentSession.search_memory` skip
  quarantined memories. `Recorder.record_memory_recall` raises `MemoryQuarantined`, so no
  code path can recall them. Forensic access needs an explicit `allow_quarantined=True`,
  and the recall is marked as forensic.
- **Quarantine never rewrites history.** It only adds nodes/flags; the memory node, its
  own `DERIVED_FROM` / `FROM` edges and every recorded Decision are untouched (checked on
  every execution: the executor compares the memory's provenance before and after and
  fails if it changed). Re-evaluating the original Day-4 action after quarantining its
  source memory gives the same verdict, the same triggered checks and the same provenance
  path. Only future retrieval changes. Regression test:
  `tests/warden/test_warden_asymmetry.py::test_quarantine_does_not_rewrite_history`.
- Policy: `quarantine_memory = ActionPolicy(outbound=False, irreversible=True, risk=low)`.
  The memories are the action's `target` argument and it has no sink, so the Guard
  normally allows it. If a tenant policy says otherwise (for example `human_review`),
  nothing is quarantined until the Guard allows it. A test covers this.

## Asymmetric remediation (`custody/warden/remediation.py`)

| Direction | Remediation | How it runs |
|---|---|---|
| tightening | `quarantine` / `disable_memory_recall`, `revoke_source_trust` | Warden Action → `Guard.enforce` → executes on ALLOW |
| loosening | `unquarantine_memory`, `endorse_data`, `restore_source_trust`, `weaken_restriction` | `propose_loosening` only: policy marks them `human_review` (forced by `harden_policy` whatever the tenant policy says), so the Guard returns REQUIRE_HUMAN_APPROVAL; a human approves (`Warden.approve_remediation` / the Guard HTTP API; the Warden and agents are refused); `execute_approved_remediation` re-runs the Guard and executes only on ALLOW |

- Every remediation is a recorded Action decided by the same Guard; nothing bypasses it. If
  a tenant policy wants a human even for a tightening action, the Warden waits.
- `revoke_source_trust` executes the existing retroactive re-adjudication
  (`revoke_and_readjudicate`): a revocation needs a human, except when it executes a
  Guard-ALLOWed Warden `revoke_source_trust` action (tightening).
- Undo is append-only: `(:QuarantineLift)-[:LIFTS]->(:Memory)` and
  `(:TrustRestoration)-[:RESTORES]->(:Source)` record who asked and which human approved;
  the original `(:Quarantine)` / `(:TrustRevocation)` stay. `restore_source_trust` only
  restores a revoked Source to its original label.
- `endorse_data` goes through `Guard.endorse` as the approving human, so data feeding a
  BLOCKed action still cannot be endorsed.
- `weaken_restriction` (e.g. a policy change) can be proposed and approved, but the Warden
  never applies it (`approved_not_applied`).
- There is no approval tool over MCP.

## Why was this allowed? (`why_allowed`)

Read-only. Re-runs the Guard (no Decision written) and returns its Provenance Completeness
Certificate plus fixed-template evidence lines rendered from it: policy result per check,
traversal status (complete, frontier exhausted, nodes, depth), context-edge and provenance
coverage (strong / downgraded), every reached root Source with its trust label (a policy
input), graph version, certificate id and the claim. It also says whether the verdict
matches the latest recorded Decision. No model writes this text; the certificate is the
source of truth. For a non-ALLOW action it says so and returns no certificate.

## Disclosure flow

**Citation-grounded claims.** Every factual sentence in a draft is a claim citing graph ids
(`custody/warden/citations.py`): "sent you a … message (Action …, Sink …)", "influenced by
an untrusted source through this recorded path (Datum … → Memory … → … → Source …)", "it
contained …(Datum …)", "it included a credential from … (Datum …, Source …)". Before the
draft is returned each claim is verified: it must cite ids, every id must exist, and every
id must belong to the traced incident (the actions, their sinks, and the complete recorded
ancestry of their arguments with its Sources). Model-written prose may be added through
`notes` (one claim per sentence, ids in `[brackets]`) or `claims=[{text, citations}]`;
unsupported sentences are removed and listed in `rejected_claims` with the reason. The
model may phrase facts; it cannot add facts the graph does not support.

```
draft_disclosure([act])        only executed + external actions; one draft per recipient,
                               recorded as a Datum (agent warden) derived from the
                               operator request, the destination and non-secret payloads.
                               Secrets appear as vault path + fingerprint suffix only.
propose_disclosure(draft)      Action send_disclosure (email sink). Recipient argument uses
                               exact-value attribution → attributed to the original trusted
                               destination. Guard: provenance checks + human_review →
                               REQUIRE_HUMAN_APPROVAL. Never auto-executed.
human approves                 Guard.approve → (:Approval)-[:APPROVES {checks:['human_review']}]
send_approved_disclosure(act)  AgentRuntime.execute → fresh Guard check → ALLOW → sent.
```

The Guard checks the Warden's disclosures like any other action. In
`test_disclosure_to_untrusted_destination_is_flagged`, a recipient that came from
untrusted content also triggers `integrity`. `harden_policy` forces `human_review` on
`send_disclosure` even when a tenant policy leaves it out. It only ever makes the policy
stricter.

## The agent

`custody/warden/agent.py`:

1. The runner calls `begin_investigation`, then lists the MCP tools.
2. A **planner** returns tool calls. These run over an MCP `Client`, which can be
   in-process, stdio or Streamable HTTP.
3. Results go back to the planner as `tool_result` blocks.
4. The loop repeats until the planner stops or `max_steps` is reached.

Planners:

- `AnthropicPlanner` uses the Claude Messages API with tool use. It needs
  `pip install anthropic` and `ANTHROPIC_API_KEY`. Set the model with
  `CUSTODY_WARDEN_MODEL` (default `claude-sonnet-5-5`).
- `PlaybookPlanner` is a deterministic, offline playbook that uses the same protocol.
  The tests and the keyless demo use it.

The agent's report lists the tools used, the quarantined ids with their Guard verdicts,
the external actions that already executed, the drafts, and **the pending approvals**. It
never claims something was sent unless `send_approved_disclosure` returned `sent=true`.

## Running

```bash
pip install -e ".[dev,warden]"

# MCP server (stdio) for any MCP client
python -m custody.warden serve --tenant acme
python -m custody.warden serve --tenant acme --seed-demo          # load the incident scenario
python -m custody.warden serve --tenant acme --transport streamable-http --port 8765   # → http://127.0.0.1:8765/mcp

# the agent
python -m custody.warden agent --tenant acme --seed-demo "That vendor page was malicious. Clean it up."
python -m custody.warden agent --tenant acme --mcp-url http://127.0.0.1:8765/mcp "..."
python scripts/warden_demo.py [--planner anthropic] [--approve]

# human approval (and send)
python -m custody.warden approve <action_id> --tenant acme --approver priya@acme-robotics.example --send
```

See the README for client configuration (Claude Desktop, Claude Code, MCP Inspector).

## Guard over MCP: what the verdict is worth

`check_action` / `explain_decision` (`custody/warden/guard_tools.py`) are adapters over
`custody.guard.Guard`; the policy logic is the same code the runtime and HTTP API use.
Two conditions sit outside Custody and are stated in each result's `enforcement` field:

1. **Complete, accurate provenance recording.** The caller must record every Datum that
   entered the model's context and link each output to all of it (the runtime's
   `AgentSession` does this; a custom integration must too). Missing edges can turn a
   dangerous action into ALLOW: the Guard can only prove things about the graph it has.
2. **Enforcement by the caller.** Over MCP Custody only answers. The caller must execute
   only on `ALLOW` and must not execute on `BLOCK`, `REQUIRE_APPROVAL` or `fail_closed`.
   Approval is not exposed over MCP (an agent cannot approve its own actions).

Tests: `tests/warden/test_guard_mcp.py` (in-process MCP client: BLOCK with evidence, ALLOW
with certificate, fail-closed on an exhausted search budget, explain matches and writes
nothing, errors are tool errors).

## Chokepoint analysis (`find_chokepoints`)

Which single provenance node must be removed to break every currently recorded untrusted
path into an action? `custody/warden/chokepoints.py`:

1. explore the Guard-followed ancestry of the destination completely (same rules as the
   integrity check);
2. keep the dangerous subgraph (nodes that reach a Datum FROM an untrusted Source);
3. count paths through each node (DAG dynamic programming; `None` if there is a cycle);
4. verify each candidate by re-running the complete integrity search with it excluded; only
   a complete NO_PATH makes it a chokepoint.

Memories (quarantinable) are recommended first; the action's own argument is reported as
trivial. Example on the primary demo: *"Memory … lies on 100% of the 4 known untrusted
path(s) … Re-running the complete integrity search with it excluded returns NO_PATH."*
This is a per-node what-if over the graph as recorded now, not a dominator/min-cut
computation. Quarantine stops future recalls; already-recorded actions keep their
provenance and verdicts. Also at `GET /tenants/{t}/console/actions/{id}/chokepoints` and in
the decision view.

## Known limits

- Warden's investigation queries (blast radius, ancestry, contamination) enumerate paths
  and are bounded by `max_trace_depth`; results deeper than that are not shown. Guard
  verdicts do not depend on this bound (see docs/guard.md, "Completeness"). Path
  enumeration can be exponential in dense multi-turn sessions, so these queries run with a
  10 s server-side timeout and fail rather than hang. Large tenants would want `algo.BFS`
  or precomputed reachability.
- `cluster_incidents` copies the whole tenant graph on every call, which is O(graph).
- Disclosure sending supports email sinks. Other channels are drafted only.
- Un-quarantining is not implemented. It would be a human-only action in the same style.
