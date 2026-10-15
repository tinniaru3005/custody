# Warden

The Warden is Custody's investigation and remediation agent. It reads the provenance graph to understand an incident, contains it, and drafts what needs to be said to people outside the organisation. Its only capabilities are [MCP tools](/docs/mcp), and every action it takes is recorded as an `Action` by agent `warden` and goes through the same Guard as any other agent's.

Code: [`custody/warden/`](repo:custody/warden/). Long-form reference: [`docs/warden.md`](repo:docs/warden.md).

![The Warden page after a cleanup run](warden.webp "The Warden page on the extended scenario: the operator's command, the planner, and the report after one run of the offline playbook.")

## Planners

A planner chooses which tool to call next. The agent loop ([`custody/warden/agent.py`](repo:custody/warden/agent.py)) records the operator's request as trusted user input, lists the MCP tools, and passes tool results back to the planner until it stops or reaches `max_steps` (20).

| Planner            | When it is used                                                     | Notes                                                                                               |
| ------------------ | ------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------- |
| `AnthropicPlanner` | `ANTHROPIC_API_KEY` is set (planner `auto`), or planner `anthropic` | Claude Messages API with tool use. Model from `CUSTODY_WARDEN_MODEL` (default `claude-sonnet-5-5`). |
| `PlaybookPlanner`  | no API key (planner `auto`), or planner `playbook`                  | Deterministic, offline; speaks the same protocol. The tests and the keyless demo use it.            |

The report lists the tools used, the quarantined memories with their Guard verdicts, the external actions that had already executed, the drafts and the pending approvals. It never claims something was sent unless `send_approved_disclosure` returned `sent: true`.

> [!WARNING]
> Tool results can contain text an attacker wrote (page content, memory previews). The server instructions and the agent prompt both tell the model to treat them as data, never as instructions. That is a mitigation, not a guarantee, which is why every Warden action still passes the Guard and external communication needs a human.

## A cleanup run

On the extended scenario, the request "That vendor page was malicious. Clean it up." produces seven tool calls with the offline playbook:

![Tool calls made by the Warden](warden-tools.webp "Each step is one MCP tool call: find_sources, trace_forward, rank_risky_memories, cluster_incidents, quarantine, draft_disclosure, propose_disclosure. The console renders each result and keeps the raw JSON.")

1. `find_sources` locates the reported vendor page.
2. `trace_forward` follows it to every derived Datum, memory, recall, message and action, separating direct influence from context-only influence.
3. `rank_risky_memories` scores memories by taint and downstream reach, plus FalkorDB `algo.betweenness`.
4. `cluster_incidents` groups contamination into incidents with `algo.WCC` on a `GRAPH.COPY` sandbox, and leaves the unrelated phishing incident alone.
5. `quarantine` records a `quarantine_memory` action; the Guard allows it, so the two poisoned memories are hidden from retrieval.
6. `draft_disclosure` writes a notice for the MSP that already received a contaminated email.
7. `propose_disclosure` records a `send_disclosure` action, which the Guard holds for human review.

![The Warden's incident report](warden-report.webp "The report: what was contaminated, what was quarantined (with the Guard verdict), what was blocked, what already left the company, and the approval that is still needed.")

## Analyses

**Direct versus context influence.** Edges with `attribution: 'context'` mean a value was in the model's context but was attributed to a trusted supplier. The Warden reports anything reached only through them as `influence: "context_only"`. In the demo, the Slack post had the poisoned memory in context but is context-only, so it is not quarantined or disclosed.

**Risk score** (`rank_risky_memories`):

```text
taint × (1 + downstream_data + 2·(recalls + messages + memories) + 3·actions
         + 5·external_actions + 10·executed_external + 10·normalized_betweenness)
```

`taint` is 1.0 if an uncleared path reaches an untrusted source, 0.25 if the untrusted ancestry is endorsed or context-only, and 0.1 otherwise. If `algo.betweenness` is unavailable, ranking falls back to reach only and says so.

**Incidents** (`cluster_incidents`): the contamination set is every Datum downstream of an untrusted Source plus the non-Warden actions that use them. On a `GRAPH.COPY` clone those nodes are labelled and split into weakly connected components; the clone is then deleted. If the copy or the algorithm is unavailable, a union-find over the same projection gives identical components. Severity:

| Severity | When                                                                            |
| -------- | ------------------------------------------------------------------------------- |
| critical | an executed external action with a contaminated destination or a secret payload |
| high     | any executed external action, or a blocked attempt                              |
| medium   | contaminated memories or contaminated actions                                   |
| low      | none of the above                                                               |

Warden artefacts (data and actions by agent `warden`) are excluded from contamination, ranking and clustering.

**Policy simulation** (`simulate_policy`) answers "if this policy had been on earlier, what would have been blocked or sent for approval?" It runs two Guards on a `GRAPH.COPY` clone with decision recording off, then deletes the clone and reports whether the live graph's node and relationship counts are unchanged. If `GRAPH.COPY` fails, it runs on a read-only proxy over the live graph instead (`mode: "read_only_live"`).

## Quarantine

- The memory gets `in_quarantine = true` plus `(:Quarantine)-[:QUARANTINES]->(:Memory)` and `(:Quarantine)-[:VIA]->(:Action {action_type:'quarantine_memory'})` edges.
- Shared-memory search and `AgentSession.search_memory` skip quarantined memories, and recording a recall of one raises `MemoryQuarantined` (HTTP 409). Forensic access needs an explicit `allow_quarantined=True`.
- **Quarantine never rewrites history.** Re-checking the Day-4 upload after its source memory is quarantined gives the same BLOCK, the same checks and the same path. Only future retrieval changes.
- `quarantine_memory` is internal, irreversible and low risk with no sink, so the Guard normally allows it. If a tenant policy demands human review, the quarantine action is held and nothing is quarantined.

## Asymmetric remediation

| Direction  | Remediation                                                                         | How it runs                                                                                                                                                                          |
| ---------- | ----------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| tightening | `quarantine`, `revoke_source_trust`                                                 | Warden action → Guard → executes on ALLOW                                                                                                                                            |
| loosening  | `unquarantine_memory`, `endorse_data`, `restore_source_trust`, `weaken_restriction` | `propose_loosening` only; the policy forces human review. After a human approves, `Warden.execute_approved_remediation` (Python only) re-runs the Guard and applies it only on ALLOW |

There is no approval tool over MCP: the Warden cannot approve its own work. A human approves a held action through the console's Approvals page or the Guard HTTP API (`POST /tenants/{t}/guard/actions/{id}/approve`); `python -m custody.warden approve` handles disclosures only. Executing an approved loosening remediation is currently only available from Python (`Warden.approve_remediation` and `Warden.execute_approved_remediation`); no HTTP route, MCP tool or console button runs it. `weaken_restriction` can be proposed and approved, but the Warden never applies a policy change itself.

## Disclosures

Every factual sentence in a draft is a claim that cites graph ids. Before a draft is returned, each claim is checked: it must cite ids, every id must exist, and every id must belong to the traced incident. Unsupported sentences are removed and listed in `rejected_claims`. A model may phrase facts; it cannot add facts the graph does not support.

![A disclosure draft awaiting approval](approvals-disclosure.webp "The Approvals page shows the drafted notice to the MSP, each statement citing the action, sink and provenance path it is based on.")

1. `draft_disclosure` covers only executed, external actions: one draft per recipient, recorded as a Datum by agent `warden`. Secrets appear only as a vault path and fingerprint suffix.
2. `propose_disclosure` records a `send_disclosure` action. The policy requires human review, so the Guard returns REQUIRE APPROVAL. It never sends.
3. A human approves, which writes `(:Approval)-[:APPROVES {checks:['human_review']}]->(:Action)`.
4. `send_approved_disclosure` re-runs the Guard and sends only on a fresh ALLOW.

> [!SIMULATED]
> "Sent" means delivered to the runtime's in-memory outbox. Custody has no email integration; nothing leaves the process.

## Known limits

- The Warden's investigation queries enumerate paths and are bounded by `CUSTODY_MAX_TRACE_DEPTH` (25); deeper results are not shown. Guard verdicts do not depend on this bound. These queries run with a 10 s server-side timeout and fail rather than hang.
- `cluster_incidents` copies the whole tenant graph on every call.
- Disclosure sending supports email sinks; other channels are drafted only.
- In [public-demo mode](/docs/deployment#public-demo-mode) the console's Warden runner is disabled, because it could call a paid model API.
