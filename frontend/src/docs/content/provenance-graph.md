# Provenance graph

Every piece of information an agent sees or produces is a node, linked to the nodes it came from. The Guard and the Warden only ever reason about this graph, so what gets recorded, and how, determines what they can find, and what a negative result ("no path found") means.

One FalkorDB graph per tenant, `custody:<tenant>`; the three-worlds comparison writes to its own graph, `custody:<tenant>-worlds`.

## Nodes

| Label              | Key properties                                                                                                                                                                                                        | What it is                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| ------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `Source`           | `id`, `kind`, **`trust`** (`trusted` / `untrusted`), `metadata`, `created_at`; after a revocation also `trust_original`, `revoked_at`, `revoked_by`                                                                   | Where information entered. Ids are deterministic: `user:<id>`, `web:<url>`, `vault:<path>`, `<kind>:<ref>` for email, GitHub or Slack content, `system:agent:<agent>`, `system:memory-store`, `system:quarantined-reader`. The first write wins: recording more data never changes an existing Source. Only an explicit trust revocation or restoration does. **`trust` is a policy input** set by whoever registers the Source; Custody does not infer it. |
| `Datum`            | `id`, `kind`, `value` (never stored for secrets), `preview`, `fingerprint` (SHA-256), **`sensitivity`** (`normal` / `sensitive` / `secret`), `endorsed`, `agent`, `session_id`, `attribution`, `coverage`, `metadata` | Any piece of information. `kind` is one of `user_input`, `web_content`, `secret`, `tool_output`, `llm_output`, `memory`, `recall`, `message`, `typed_value`.                                                                                                                                                                                                                                                                                                |
| `Datum:Memory`     | + `metadata.key`, `in_quarantine`, `quarantine_id`                                                                                                                                                                    | A memory saved to shared storage.                                                                                                                                                                                                                                                                                                                                                                                                                           |
| `Datum:Recall`     | + `metadata.memory_id`, `metadata.query`                                                                                                                                                                              | One retrieval of a memory into a session.                                                                                                                                                                                                                                                                                                                                                                                                                   |
| `Datum:Message`    | + `metadata.sender`, `metadata.recipient`, `metadata.thread_id`                                                                                                                                                       | An inter-agent message.                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| `Datum:Typed`      | + `quarantined`, `value_type`, `max_risk` (`low` / `high`, default `low`)                                                                                                                                             | A validated value pulled out of untrusted content by the [quarantined reader](#the-quarantined-typed-reader), `FROM system:quarantined-reader`.                                                                                                                                                                                                                                                                                                             |
| `Action`           | `id`, `action_type`, `agent`, `status`, `session_id`, `metadata`                                                                                                                                                      | A side effect an agent proposes. `status` is `proposed`, `pending_approval`, `approved`, `blocked`, `rejected`, `executed` or `failed`.                                                                                                                                                                                                                                                                                                                     |
| `Sink`             | `id` (hash of kind, workspace and destination), `destination`, `kind`, `external`, `workspace`                                                                                                                        | Where an action sends data. Shared between actions with the same kind, workspace and destination. `external` as declared is advisory; the Guard re-classifies every sink.                                                                                                                                                                                                                                                                                   |
| `Approval`         | `approver`, `approver_kind`, `verdict` (`approved` / `rejected`), `reason`, `egress`                                                                                                                                  | A human endorsement, action-scoped approval or rejection.                                                                                                                                                                                                                                                                                                                                                                                                   |
| `Decision`         | `action_id`, `decision`, `triggered`, `explanation`, `latency_ms`, `policy`                                                                                                                                           | Audit record of one Guard evaluation.                                                                                                                                                                                                                                                                                                                                                                                                                       |
| `Quarantine`       | `actor`, `reason`, `action_id`, `incident_id`                                                                                                                                                                         | Warden containment record.                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| `QuarantineLift`   | `lifted_by`, `approved_by`, `action_id`                                                                                                                                                                               | A human-approved end of a quarantine.                                                                                                                                                                                                                                                                                                                                                                                                                       |
| `TrustRevocation`  | `source_id`, `revoked_by`, `reason`, `trust_before`                                                                                                                                                                   | A Source marked untrusted after the fact (see [re-adjudication](/docs/guard#retroactive-re-adjudication)).                                                                                                                                                                                                                                                                                                                                                  |
| `TrustRestoration` | `source_id`, `restored_by`, `approved_by`, `action_id`                                                                                                                                                                | A human-approved undo of a revocation.                                                                                                                                                                                                                                                                                                                                                                                                                      |
| `Readjudication`   | `source_id`, `original_verdict`, `current_verdict`, `transition`                                                                                                                                                      | One re-run of the current Guard on a historical action after a revocation.                                                                                                                                                                                                                                                                                                                                                                                  |

Two bookkeeping labels are never traversed as provenance: `GraphMeta` (write counters; the graph version that certificates cite) and `Run` (stored demo, worlds, Warden and re-adjudication reports). Memory keys, recall queries and message senders live inside the `metadata` JSON text, not as separate properties.

Reference for every field: [`docs/graph-model.md`](repo:docs/graph-model.md) and [`custody/graph/model.py`](repo:custody/graph/model.py).

## Relationships

```cypher
(:Datum)-[:FROM]->(:Source)                      // where it entered
(:Datum)-[:DERIVED_FROM {op, attribution}]->(:Datum)
        // op: derive | save | recall | send | attribute | extract
        // attribution: inherit | exact | context   (the Guard never follows 'context')
(:Action)-[:ARG {role}]->(:Datum)                // role: destination | payload | <custom>
(:Action)-[:TO]->(:Sink)
(:Approval)-[:ENDORSES {egress}]->(:Datum)       // a human vouches for data (sets endorsed = true);
                                                 // egress: also pre-approves secret egress to this value
(:Approval)-[:APPROVES {checks}]->(:Action)      // action-scoped approval of Guard checks
(:Approval {verdict:'rejected'})-[:REJECTS]->(:Action)  // clears nothing; feeds precedent
(:Decision)-[:EVALUATES]->(:Action)              // Guard audit trail
(:Quarantine)-[:QUARANTINES]->(:Datum:Memory)    // Warden containment
(:Quarantine)-[:VIA]->(:Action)                  // the Guard-checked quarantine_memory action
(:QuarantineLift)-[:LIFTS {quarantine_id}]->(:Datum:Memory)
(:TrustRevocation)-[:REVOKES]->(:Source)
(:TrustRevocation)-[:PRODUCED]->(:Readjudication)-[:READJUDICATES]->(:Action)
(:TrustRestoration)-[:RESTORES]->(:Source)
```

Memories, recalls and messages all carry the `Datum` label, so one traversal over `DERIVED_FROM` crosses model turns, saved memories, later sessions that recall them, and messages between agents without special cases. A recall is its own node rather than an edge to the memory, so each time a memory surfaces the graph keeps the session, agent and query that retrieved it.

## The primary demo as a graph

The path the Guard reports for the blocked upload in the demo:

<figure class="diagram">
<svg viewBox="0 0 760 196" role="img" aria-labelledby="pg-t pg-d">
<title id="pg-t">Provenance path behind the blocked upload</title>
<desc id="pg-d">The upload_backup action has a destination argument derived from a memory that Scout saved on Day 1, which was derived from a web page that came from an untrusted source.</desc>
<defs><marker id="pg-a" viewBox="0 0 8 8" refX="7" refY="4" markerWidth="8" markerHeight="8" orient="auto-start-reverse"><path class="dg-arrow" d="M0,0 L8,4 L0,8 z"/></marker></defs>
<rect class="dg-box dg-bad" x="16" y="30" width="128" height="62" rx="8"/>
<text class="dg-h" x="28" y="54">Action</text>
<text class="dg-code" x="28" y="74">upload_backup</text>
<rect class="dg-box dg-secret" x="166" y="30" width="128" height="62" rx="8"/>
<text class="dg-h" x="178" y="54">Datum</text>
<text class="dg-m" x="178" y="72">destination arg</text>
<text class="dg-m" x="178" y="86">Ops · Day 4</text>
<rect class="dg-box" x="316" y="30" width="128" height="62" rx="8"/>
<text class="dg-h" x="328" y="54">Memory</text>
<text class="dg-m" x="328" y="72">team-backup-dest.</text>
<text class="dg-m" x="328" y="86">Scout · Day 1</text>
<rect class="dg-box" x="466" y="30" width="128" height="62" rx="8"/>
<text class="dg-h" x="478" y="54">Datum</text>
<text class="dg-m" x="478" y="72">web page content</text>
<text class="dg-m" x="478" y="86">Scout · Day 1</text>
<rect class="dg-box dg-bad" x="616" y="30" width="128" height="62" rx="8"/>
<text class="dg-h" x="628" y="54">Source</text>
<text class="dg-m" x="628" y="72">web: vendor page</text>
<text class="dg-m" x="628" y="86">untrusted</text>
<path class="dg-line" d="M144 61 H160" marker-end="url(#pg-a)"/>
<path class="dg-line" d="M294 61 H310" marker-end="url(#pg-a)"/>
<path class="dg-line" d="M444 61 H460" marker-end="url(#pg-a)"/>
<path class="dg-line" d="M594 61 H610" marker-end="url(#pg-a)"/>
<text class="dg-code" x="139" y="22">ARG</text>
<text class="dg-code" x="281" y="22">DERIVED_FROM</text>
<text class="dg-code" x="436" y="22">save</text>
<text class="dg-code" x="596" y="22">FROM</text>
<rect class="dg-box dg-secret" x="166" y="122" width="128" height="56" rx="8"/>
<text class="dg-h" x="178" y="146">Datum</text>
<text class="dg-m" x="178" y="164">payload: new key</text>
<rect class="dg-box" x="466" y="122" width="128" height="56" rx="8"/>
<text class="dg-h" x="478" y="146">Source</text>
<text class="dg-m" x="478" y="164">vault (trusted)</text>
<path class="dg-line" d="M80 92 V150 H160" marker-end="url(#pg-a)"/>
<path class="dg-line" d="M294 150 H460" marker-end="url(#pg-a)"/>
<text class="dg-code" x="92" y="142">ARG payload</text>
<text class="dg-code" x="330" y="142">secret, from the vault</text>
</svg>
<figcaption>Two hops from the destination to the untrusted page. Longer routes (through Ops' recall of the memory) are recorded too and shown as extra evidence.</figcaption>
</figure>

![The provenance graph page with the blocked path highlighted](graph-nodes.webp "The Provenance graph page draws every node; the path behind the blocked action is animated in red.")

## The recording rule

Every negative result ("no path to an untrusted source", and therefore ALLOW) is relative to the recorded graph and the current Source trust labels, and depends on one recording assumption: **the graph does not silently omit a context dependency.** The agent runtime ([`custody/runtime/runtime.py`](repo:custody/runtime/runtime.py)) enforces the rule:

> Every model output, tool-call argument, memory and message gets a `DERIVED_FROM` edge to everything in the session's context window. `derived_from=` can add parents but never narrow the context. Everything shown to the model enters the context: user input, fetched pages, vault reads, recalls, memory-search results, received messages, typed values.

This deliberately over-approximates influence. The graph may report influence that did not happen (a false alarm), but it does not drop a dependency it was told about. (One deliberate exception: a [typed value](#the-quarantined-typed-reader) derives only from the content it was extracted from, because the quarantined reader is a separate model call whose context is exactly that content.)

Consequences you should know about:

- **Over-approximation costs false positives.** A value the user typed but the model re-wrote (normalised, reformatted) is attributed to the whole context, including any untrusted page in it.
- **Sensitivity creeps.** A Datum without an explicit sensitivity takes the highest sensitivity of its parents. An argument produced while a secret was in context is labelled secret, because the value could encode the key. In the demo, the attacker URL is therefore masked in the graph.
- **What Custody cannot see** is influence that never passes through the recorder, and implicit flows (an untrusted page influencing _which_ trusted value the model picks). An integration calling the HTTP API must pass the complete context as `derived_from`, or declare `coverage: "REDUCED"`; see [Recording your own agents](/docs/integrating).

So the strongest negative statement Custody makes is: relative to the recorded provenance graph, current trust labels, and a complete traversal, no untrusted influence path was found. It never says an action is safe.

## Exact-value attribution (label creep)

Without a correction, label creep would make every value untrusted within a few turns: once a poisoned memory is in context, everything the model writes derives from it.

The runtime records each tool argument with `attribution="exact"`. If a **trusted** Datum in or behind the context (candidates are looked up within `CUSTODY_MAX_TRACE_DEPTH` hops, default 25) supplied exactly that value, the argument gets one edge `DERIVED_FROM {op:'attribute', attribution:'exact'}` to the supplier. The other context items are still linked, but with `attribution:'context'`, which the Guard does not follow. Sensitivity is then taken from the suppliers only.

- "Exact" means a whole-value fingerprint match (the only way secrets can match, since their raw value is never stored) or a whole-token match in the supplier's text. `board@acme-robotics.example` does **not** match inside `board@acme-robotics.example.evil.example`.
- A supplier counts as trusted only if a complete traversal over the edges the Guard follows finds no path to an untrusted Source without an endorsed Datum on it (`NO_PATH`). A path found, or an incomplete search, disqualifies it.
- If there is no trusted supplier (or a candidate lies beyond the lookup bound), the argument falls back to inheriting from the whole context. The bound can only cost an exact attribution, never hide a dependency.

That is why step 5 of the demo is allowed: `#platform-team` is exactly what Sam typed, so the destination is attributed to Sam even though the poisoned memory was in Ops' context.

## Provenance coverage

Every model-produced Datum (`llm_output`, `memory`, `message`, `typed_value`) stores a `coverage` value:

| `coverage`     | Meaning                                                                                                                         |
| -------------- | ------------------------------------------------------------------------------------------------------------------------------- |
| `FULL_CONTEXT` | `DERIVED_FROM` edges to everything in the producing call's context window. The default, and what `AgentSession` always records. |
| `REDUCED`      | A narrower attribution was used (declare it with `coverage: "REDUCED"` on the Recorder or HTTP API).                            |
| missing        | Older data; treated as `REDUCED`.                                                                                               |

Coverage does not change verdicts. It qualifies the [provenance completeness certificate](/docs/guard#provenance-completeness-certificate) attached to an ALLOW: any `REDUCED` output in the ancestry downgrades it.

## The quarantined (typed) reader

`Recorder.record_typed_value` (`AgentSession.extract_typed`) pulls a value out of untrusted content and validates it against a narrow type: `int`, `number`, `bool`, `date`, `enum`, `ticket_id` or `currency`. Free-form types such as email addresses, URLs and text are refused. The value is stored as `:Datum:Typed` (`FROM system:quarantined-reader`, derived only from the content it was extracted from) with `quarantined = true` and `max_risk` (`'low'` by default; `Recorder.record_typed_value` accepts `max_risk="high"`). An untrusted path through such a node clears only for actions whose risk tier is at most `max_risk`: with the default, it is reported as `limited` and allowed for low-risk actions such as `update_ticket`, and is still a violation for high-risk ones. Which value the reader picked remains its choice; that implicit channel is out of scope.

## Invariants

- **Provenance is append-only; a few flags are not.** Datums and their `FROM`, `DERIVED_FROM`, `ARG` and `TO` edges are never changed or deleted, and new Datums only point at older ones, so the recorded ancestry of an existing Datum never changes. The fields that do change in place, each next to an audit node, are `Datum.endorsed` (Approval), `Action.status` (Decision / Approval), `Memory.in_quarantine` / `quarantine_id` (set by a Quarantine, cleared by an approved QuarantineLift), and `Source.trust` (TrustRevocation / TrustRestoration, with the original label kept in `trust_original`). These change what a _later_ Guard check concludes; they never rewrite earlier Decisions.
- **Every Datum has exactly one `FROM` edge.** Agent outputs come from `system:agent:<agent>`, recalls from `system:memory-store`, typed values from `system:quarantined-reader`.
- **Raw secret values are never written.** Only a masked `preview` and the `fingerprint` are stored.
- **Trust is never copied onto data.** It lives on Sources and is computed per path at decision time, so labels cannot drift.
- **Writes are validated first.** Parents and action arguments are checked before the Datum or Action is written; a missing id raises `NotFound` (HTTP 404). The one exception: recording a model output, memory or message creates the agent's `system:agent:<agent>` Source (a typed value: `system:quarantined-reader`) before the parents are checked, so that Source can remain after a failed write.
