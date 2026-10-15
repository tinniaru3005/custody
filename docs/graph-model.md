# Custody graph model

One FalkorDB graph per tenant: `custody:<tenant>` (e.g. `custody:acme`). Tenant slugs are
validated (`[a-z0-9][a-z0-9_-]{0,62}`) before they are turned into graph names.

## Nodes

| Label | Key properties | Notes |
|---|---|---|
| `Source` | `id`, `kind` (user, web, vault, email, github, slack, system), `trust` (trusted, untrusted), `metadata` (JSON), `created_at` | Where information came in. Ids are deterministic (`user:<id>`, `web:<url>`, `vault:<path>`, `system:agent:<agent>`, `system:memory-store`). Merged on id; the first write wins. |
| `Datum` | `id`, `kind`, `value` (not stored for secrets), `preview`, `fingerprint` (sha256), `sensitivity` (normal, sensitive, secret), `endorsed`, `created_at`, `agent`, `session_id`, `metadata` | Any piece of information. |
| `Datum:Memory` | + `metadata.key` | A memory saved to shared storage. |
| `Datum:Recall` | + `metadata.memory_id`, `metadata.query` | One retrieval of a memory into a session. |
| `Datum:Message` | + `metadata.sender/recipient/thread_id` | An inter-agent message. |
| `Action` | `id`, `action_type`, `agent`, `status` (proposed, approved, blocked, executed, failed), `created_at`, `session_id` | A side effect an agent proposes. |
| `Sink` | `id` (hash of kind and destination), `destination`, `kind`, `external` | Shared between actions that target the same place. |
| `Datum:Typed` | + `quarantined`, `value_type`, `max_risk` | A validated value extracted by the quarantined reader. |
| `Approval` | `id`, `approver`, `approver_kind`, `reason`, `verdict` (`approved`/`rejected`), `created_at` | A human endorsement, approval or rejection. |
| `Decision` | `id`, `action_id`, `decision`, `triggered`, `explanation`, `latency_ms`, `policy`, `created_at` | Audit record of one Guard evaluation. |
| `Quarantine` | `id`, `actor` (`warden`), `reason`, `action_id`, `incident_id`, `created_at` | Warden containment record. |
| `Run` | `id`, `kind` (`demo`, `warden`), `payload` (JSON), `created_at` | Stored console reports (demo story, last Warden run). Not provenance; never traversed. |

Memories put in quarantine by the Warden get `in_quarantine = true` and `quarantine_id`.
This is deliberately a different property from `Datum:Typed.quarantined`, which marks a
value from the quarantined *reader* and makes the Guard treat a path as *limited*.

`Datum.kind` is one of: `user_input`, `web_content`, `secret`, `tool_output`, `llm_output`,
`memory`, `recall`, `message`, `typed_value`. Every Datum also has `attribution`
(`inherit` or `exact`).

`Action.status` is one of: `proposed`, `pending_approval`, `approved`, `blocked`, `rejected`,
`executed`, `failed`.

## Relationships

```
(:Datum)-[:FROM]->(:Source)
(:Datum)-[:DERIVED_FROM {op, attribution}]->(:Datum)
        op: derive | save | recall | send | attribute | extract
        attribution: inherit | exact | context   (the Guard never follows 'context')
(:Action)-[:ARG {role}]->(:Datum)           role: destination | payload | <custom>
(:Action)-[:TO]->(:Sink)
(:Approval)-[:ENDORSES]->(:Datum)           also sets Datum.endorsed = true
(:Approval)-[:APPROVES {checks}]->(:Action)  action-scoped approval of Guard checks
(:Approval {verdict:'rejected'})-[:REJECTS]->(:Action)  a human said no (clears nothing)
(:Decision)-[:EVALUATES]->(:Action)         Guard audit trail
(:Quarantine)-[:QUARANTINES]->(:Datum:Memory) Warden containment
(:Quarantine)-[:VIA]->(:Action)             the Guard-checked quarantine_memory action
```

## Why Memory, Recall and Message are all Datums

Each of them carries the `:Datum` label, so one traversal,
`(d)-[:DERIVED_FROM*]->(ancestor)`, crosses LLM turns, saved memories, later sessions
that recall them, and messages between agents:

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

- The graph only grows. The only fields that change after creation are `Datum.endorsed`
  (set by an approval), `Action.status`, and `Memory.in_quarantine` / `quarantine_id`
  (set by a Guard-checked Warden quarantine; it hides the memory from retrieval and
  never changes provenance). New Datums only point at older ones, so the
  ancestry of an existing Datum never changes.
- Every Datum has exactly one `FROM` edge. Agent outputs come `FROM system:agent:<agent>`
  and recalls come `FROM system:memory-store`.
- Raw secret values are never written. Only `preview`, which is masked, and `fingerprint`
  are stored.
- Sensitivity is inherited: if a derived Datum doesn't set it, it takes the highest
  sensitivity among its parents.
- Trust is not copied onto data. It belongs to Sources and has to be worked out by walking
  lineage (`Lineage.untrusted_sources`).
- Parents and action arguments are checked before anything is written, so a missing id
  raises `NotFound` and leaves the graph unchanged.

## Read API (facts only)

- `lineage(datum_id)`: every ancestor Datum with its minimum depth and Source.
- `find_paths(from_id, to_id)` / `find_path(...)`: concrete provenance paths with the
  `op` of each hop, shortest first.
- `trace_action(action_id)`: the lineage of each argument (destination, payload, …) plus
  the sink.

These reads make no policy decisions. Policy belongs to the Guard: see [guard.md](guard.md).
