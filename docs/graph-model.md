# Custody graph model

One FalkorDB graph per tenant: `custody:<tenant>` (e.g. `custody:acme`). Tenant slugs are
validated (`[a-z0-9][a-z0-9_-]{0,62}`) before they are turned into graph names. The
three-worlds comparison writes to its own graph, `custody:<tenant>-worlds`.

Code: `custody/graph/schema.py` (labels, relationship types, indexes), `model.py` (records),
`repository.py` (Cypher), `traversal.py` (complete searches).

## Nodes

### Provenance

| Label | Key properties | Notes |
|---|---|---|
| `Source` | `id`, `kind` (user, web, vault, email, github, slack, system), `trust` (trusted, untrusted), `metadata` (JSON), `created_at`; after a revocation also `trust_original`, `revoked_at`, `revoked_by`, and after a restoration `restored_at` | Where information came in. Ids are deterministic (`user:<id>`, `web:<url>`, `vault:<path>`, `system:agent:<agent>`, `system:memory-store`, `system:quarantined-reader`). Merged on id; the first write wins. **`trust` is a policy input** set by whoever registers the Source; Custody does not infer it. |
| `Datum` | `id`, `kind`, `value` (not stored for secrets), `preview`, `fingerprint` (sha256), `sensitivity` (normal, sensitive, secret), `endorsed`, `coverage`, `attribution`, `created_at`, `agent`, `session_id`, `metadata` | Any piece of information. |
| `Datum:Memory` | + `metadata.key`, `in_quarantine`, `quarantine_id` | A memory saved to shared storage. |
| `Datum:Recall` | + `metadata.memory_id`, `metadata.query` | One retrieval of a memory into a session. |
| `Datum:Message` | + `metadata.sender/recipient/thread_id` | An inter-agent message. |
| `Datum:Typed` | + `quarantined`, `value_type`, `max_risk` (low, high; default low) | A validated value extracted by the quarantined reader (`FROM system:quarantined-reader`). The Guard treats it as clearing an integrity path only for actions whose risk tier is at most `max_risk`. |
| `Action` | `id`, `action_type`, `agent`, `status`, `metadata`, `created_at`, `session_id` | A side effect an agent proposes. |
| `Sink` | `id` (hash of kind, workspace and destination), `destination`, `kind`, `external`, `workspace` | Shared between actions that target the same place. |

`Datum.kind` is one of: `user_input`, `web_content`, `secret`, `tool_output`, `llm_output`,
`memory`, `recall`, `message`, `typed_value`. `Datum.attribution` is `inherit` or `exact`.

`Datum.coverage` (model-produced kinds: `llm_output`, `memory`, `message`, `typed_value`) is
`FULL_CONTEXT` (edges to the whole context window: the default and what `AgentSession`
records) or `REDUCED` (declared by an integrator whose `derived_from` is narrower). It
qualifies the certificate; see [guard.md](guard.md#provenance-completeness-certificate).

`Action.status` is one of: `proposed`, `pending_approval`, `approved`, `blocked`, `rejected`,
`executed`, `failed`.

Memories put in quarantine get `in_quarantine = true` and `quarantine_id`. This is
deliberately a different property from `Datum:Typed.quarantined`, which marks a value from
the quarantined *reader*.

### Human decisions, audit and containment

| Label | Key properties | Notes |
|---|---|---|
| `Approval` | `id`, `approver`, `approver_kind`, `reason`, `verdict` (`approved` / `rejected`), `egress`, `created_at` | A human endorsement, action-scoped approval or rejection. |
| `Decision` | `id`, `action_id`, `decision`, `triggered`, `explanation`, `latency_ms`, `policy`, `created_at` | Audit record of one Guard evaluation (enforcement, `check_action`, or a console check). |
| `Quarantine` | `id`, `actor`, `reason`, `action_id`, `incident_id`, `created_at` | Containment record written by the Guard-checked `quarantine_memory` action. |
| `QuarantineLift` | `id`, `lifted_by`, `approved_by`, `action_id`, `created_at` | A human-approved end of a quarantine (Warden loosening). |
| `TrustRevocation` | `id`, `source_id`, `revoked_by`, `reason`, `created_at` | A Source marked untrusted after the fact. |
| `TrustRestoration` | `id`, `source_id`, `restored_by`, `approved_by`, `created_at` | A human-approved undo of a revocation. |
| `Readjudication` | the action, original verdict, current verdict, transition | One re-run of the current Guard on a historical action after a revocation. |

### Bookkeeping (never traversed as provenance)

| Label | Notes |
|---|---|
| `GraphMeta` | write counters (`started` / `finished`): the graph version used by certificates. Provenance writes, action-status changes, approvals, quarantines/lifts and trust changes bump it; Decision and Run records do not. |
| `Run` | stored console reports: `kind` ∈ `demo`, `worlds`, `warden`, `readjudication`; `payload` (JSON). |

## Relationships

```
(:Datum)-[:FROM]->(:Source)
(:Datum)-[:DERIVED_FROM {op, attribution}]->(:Datum)
        op: derive | save | recall | send | attribute | extract | …
        attribution: inherit | exact | context   (the Guard never follows 'context')
(:Action)-[:ARG {role}]->(:Datum)              role: destination | payload | <custom>
(:Action)-[:TO]->(:Sink)
(:Approval)-[:ENDORSES {egress}]->(:Datum)     also sets Datum.endorsed = true;
                                               egress: also pre-approves secret egress
                                               to the destination value this Datum holds
(:Approval)-[:APPROVES {checks}]->(:Action)    action-scoped approval of Guard checks
(:Approval {verdict:'rejected'})-[:REJECTS]->(:Action)   a human said no (clears nothing;
                                               feeds precedent escalation)
(:Decision)-[:EVALUATES]->(:Action)            Guard audit trail
(:Quarantine)-[:QUARANTINES]->(:Datum:Memory)  containment
(:Quarantine)-[:VIA]->(:Action)                the Guard-checked quarantine_memory action
(:QuarantineLift)-[:LIFTS {quarantine_id}]->(:Datum:Memory)
(:TrustRevocation)-[:REVOKES]->(:Source)
(:TrustRevocation)-[:PRODUCED]->(:Readjudication)-[:READJUDICATES]->(:Action)
(:TrustRestoration)-[:RESTORES]->(:Source)
```

## Why Memory, Recall and Message are all Datums

Each of them carries the `:Datum` label, so one traversal over `DERIVED_FROM` crosses LLM
turns, saved memories, later sessions that recall them, and messages between agents:

```
web page (untrusted) ─┐
user ask ─────────────┴─< summary (research, S1) <─save── Memory <─recall── Recall (ops, S2)
                                   ▲                                          ▲
                                   └──send── Message (research→ops) ──────────┤
                                                                 derive       │
                                                         dest (ops, S2) ──────┘
                                                              ▲ ARG{destination}
                                                     Action send_email ──TO──> Sink
```

A recall is stored as its own node rather than as an edge to the memory. That way each
time a memory surfaces, the record keeps the session, agent and query, and outputs in the
recalling session point at that specific recall.

## Invariants

- **Provenance is append-only.** Datums and their `FROM`, `DERIVED_FROM`, `ARG` and `TO`
  edges are never changed or deleted, and new Datums only point at older ones, so the
  recorded ancestry of an existing Datum never changes.
- **A few flags change in place, each next to an audit node:** `Datum.endorsed`
  (Approval), `Action.status` (Decision / Approval), `Memory.in_quarantine` /
  `quarantine_id` (Quarantine / QuarantineLift; hides the memory from normal retrieval and
  recall, never changes provenance), and `Source.trust` (TrustRevocation /
  TrustRestoration, with the original label kept in `trust_original`). These change what a
  *later* Guard re-check concludes; they never rewrite earlier Decisions.
- Every Datum has exactly one `FROM` edge. Agent outputs come `FROM system:agent:<agent>`
  and recalls come `FROM system:memory-store`.
- Raw secret values are never written. Only `preview`, which is masked, and `fingerprint`
  are stored.
- Sensitivity is inherited: if a derived Datum doesn't set it, it takes the highest
  sensitivity among its parents.
- Trust is not copied onto data. It belongs to Sources and is evaluated by walking
  provenance at decision time.
- Parents and action arguments are checked before the Datum or Action is written, so a
  missing id raises `NotFound` (HTTP 404). One exception: recording a model output, memory
  or message creates the agent's `system:agent:<agent>` Source (for a typed value,
  `system:quarantined-reader`) before the parents are checked, so that Source can remain
  after a failed write.

## Read API (facts only)

- `lineage(datum_id)`: ancestor Datums with their minimum depth and Source, within
  `CUSTODY_MAX_TRACE_DEPTH` hops (default 25).
- `find_paths(from_id, to_id)` / `find_path(...)`: concrete provenance paths with the
  `op` of each hop, shortest first, within the same bound.
- `trace_action(action_id)`: the lineage of each argument (destination, payload, …) plus
  the sink.

These reads are bounded views for people and make no policy decisions. Guard verdicts use
the complete searches in `traversal.py` instead: see [guard.md](guard.md#completeness-path_found--no_path--indeterminate).
