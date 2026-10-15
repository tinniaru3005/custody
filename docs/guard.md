# Custody Guard

The Guard decides whether an agent's outbound or irreversible action may run. It is
**deterministic**: no LLM is consulted. Each decision is a pure function of

1. facts returned by FalkorDB Cypher provenance queries (`custody/guard/queries.py`), and
2. the tenant's static `GuardPolicy` (`custody/guard/policy.py`): which actions are
   guarded, which destinations are internal.

Code: `custody/guard/` (Guard, policy, queries, decision models), `custody/runtime/`
(agent runtime that enforces it), `custody/api/routes/guard.py` (HTTP).

## Threat model

In scope: **explicit data flow that the runtime records** — every user message, web page,
tool output, vault read, LLM output, memory, recall and inter-agent message is a `Datum`
with `DERIVED_FROM` edges to what produced it. An attacker controls the content of
untrusted Sources (web pages, inbound email, GitHub issues, ...).

Out of scope: **implicit flows through the model's internal reasoning.** If an untrusted
page convinces the model to *choose* one trusted value over another (e.g. pick
`#security` over `#general`, both of which the user typed), the graph sees a value the
user supplied and the Guard treats it as trusted. Timing and other side channels are also
out of scope. Exact-value attribution relies on this boundary on purpose.

Assumptions: the runtime records context faithfully (an LLM output is linked to every
Datum that was in its context); approvers are humans authenticated outside Custody.

## Checks

Run for every action whose policy is outbound or irreversible (unknown action types are
treated as outbound, irreversible and high risk).

| Check | Fires when | Query |
|---|---|---|
| **Integrity** | a destination argument traces to an untrusted Source with **no endorsed Datum on that path**, or the sink's literal destination is not bound to any recorded destination Datum | `integrity_paths`, `destination_binding` |
| **Confidentiality** | a non-destination argument (payload) traces to a Datum with `sensitivity = 'secret'` **and** the sink is external | `confidentiality_paths` |
| **Lethal trifecta** | integrity violated **and** payload secret **and** sink external | both of the above |

```cypher
// integrity (simplified): worst paths first
MATCH (a:Action {id:$aid})-[arg:ARG]->(d:Datum) WHERE arg.role IN $roles
MATCH p = (d)-[:DERIVED_FROM*0..25]->(x:Datum)
WHERE all(r IN relationships(p) WHERE coalesce(r.attribution,'inherit') <> 'context')
MATCH (x)-[:FROM]->(s:Source {trust:'untrusted'})
WITH ..., [n IN nodes(p) WHERE n.endorsed = true | n.id] AS endorsed_ids,
          [n IN nodes(p) WHERE n.quarantined = true | n.id] AS typed_ids
RETURN ... ORDER BY size(endorsed_ids), size(typed_ids), length(p) LIMIT $limit
```

All traversals are variable-length, so they cross any number of LLM turns, memories,
recalls, messages, sessions and agents. The path queries above are bounded by
`GuardPolicy.max_depth` (25) and only supply **evidence** (paths for the explanation/UI).

### Completeness: PATH_FOUND / NO_PATH / INDETERMINATE

"No path within 25 hops" is not "no path". The **verdict** for integrity and
confidentiality comes from a complete reachability search (`custody/graph/traversal.py`):
a level-by-level BFS with a visited set (cycle-safe, each node expanded once, no depth
bound by default) that applies the same edge/node rules as the queries above (skip
`context` edges; stop at endorsed Datums and, for integrity, at typed Datums that cover the
action's risk). Each search returns one of:

| Outcome | Meaning | Treated as |
|---|---|---|
| `PATH_FOUND` | a relevant path exists (witness path attached as evidence) | violation |
| `NO_PATH` | traversal exhausted the reachable graph | clean |
| `INDETERMINATE` | did not finish: `depth_limit`, `node_limit`, `timeout`, `query_error` | **violation (fail closed)** |

A check passes only when `path_found = false` **and** `search_complete = true`. Each
`CheckResult.search` carries `outcome`, `path_found`, `search_complete`,
`termination_reason`, `max_depth_reached`, `depth_explored`, `nodes_visited`, `queries`,
`latency_ms` and `error`; the decision carries `search_complete` and
`indeterminate_checks`. Consequences of `INDETERMINATE`:

- never `ALLOW`; if a lethal trifecta cannot be ruled out → `BLOCK`;
- otherwise `REQUIRE_HUMAN_APPROVAL` with **no approval option** (there is nothing concrete
  to approve) and action-scoped approvals do not clear it; a later re-check that completes
  decides normally.

The same complete search backs the `endorse()` refusal check (data feeding a blocked
action cannot be endorsed; an incomplete search refuses), the Recorder's exact-value
attribution candidates and lineage views. Variable-length `*0..N` patterns enumerate
*paths*, which is exponential in dense DAGs (a multi-turn session where every output derives
from every earlier one has ≈2^t paths), so they are only used for evidence, with
`GuardPolicy.evidence_timeout_ms` (250 ms). When the evidence query times out, the decision
keeps the search's witness path as evidence; the verdict is unaffected.

**Any route, not the shortest.** The verdict is "does any uncleared route exist". The
evidence query orders rows uncleared-first, then shortest, so the explanation shows the
shortest *uncleared* route; if the evidence query finds none (all its rows cleared, its
LIMIT or depth reached, or it failed) the complete search runs anyway. Length is never an
input to the verdict. Regression tests: `tests/guard/test_any_route.py` (short trusted route
beside a 1–60-hop untrusted route; shortest untrusted route endorsed, longer one not, with
`path_limit=1` and evidence depth 3; evidence query failing; fail-closed node budget).

**Distinct roots and route independence** (`custody/guard/contamination.py`,
`GuardDecision.contamination`, after the verdict, only when integrity found a route):
`root_count` / `roots_complete` from one BFS over the followed ancestry; a shortest route
per root from the BFS tree; `independence` ∈ `independent` (method `disjoint_routes`: a
route found with route 1's Datums excluded; or `no_single_shared_datum`: excluding each
Datum of route 1 alone leaves a route, so by Menger two disjoint routes exist),
`converging` (`shared_datum_id`: excluding it leaves no route, verified), `direct` (the
argument is untrusted content), `unverified` (a search was incomplete or the budget of
`contamination_max_checks` searches / `contamination_timeout_ms` ran out). Independence
means no shared Datum after the argument. A failure here leaves the verdict untouched and
the report empty.

Limits: `GuardPolicy.search_max_depth` (default `None` = unbounded),
`search_max_nodes` (100 000), `search_timeout_ms` (2 000; also passed to FalkorDB as the
per-query timeout). Cost: one read query per BFS level (~0.6 ms/level on embedded FalkorDB);
a found path stops early. Measured in [bench/README.md](../bench/README.md).

### Provenance Completeness Certificate

Every ALLOW from the provenance checks gets `GuardDecision.certificate`
(`ProvenanceCertificate`), or `certificate_unavailable` with the reason. It builds on the
verdict's search, it does not replace it:

1. The integrity search must be a complete `NO_PATH` (`search_complete`, termination
   `exhausted`). Its visited set is the set of nodes on Guard-followed paths.
2. A second traversal (`traversal.ancestor_graph`) walks the **complete recorded ancestor
   graph** of the destination argument(s): every `DERIVED_FROM` edge, including
   `attribution: "context"` edges recorded for everything in the LLM's context window, with
   no pruning, then reads the `FROM` Source of every Datum reached. Same limits; if it is
   not exhausted, there is no certificate (the ALLOW itself still rests on step 1).
3. Each reachable Source is classified: `followed` (on a Guard-followed path; never
   untrusted for an ALLOW, checked), `context_only` (reached only via context edges:
   exact-value attribution found a trusted supplier) or `cleared` (every followed path
   passes through human-endorsed or typed data).
4. The graph version is read before and after: `GraphMeta.started/finished` count every
   provenance write (`GraphRepository._q` brackets each write; Decision and Run audit
   records don't count). The certificate requires `started == finished` (no write in
   flight) and no change during the check, and records `graph@vN` plus
   `ancestry_digest = sha256(examined nodes + flags, edges + attribution, FROM sources)`,
   which is stable across unrelated writes and changes if the examined ancestry does.

The claim begins, verbatim: *"No untrusted influence was found relative to the recorded
provenance graph (graph version V) and current Source trust labels."* It certifies the
recorded graph only: unrecorded influence (implicit flows, integrators omitting context) is
outside it, and it never says "safe".

**Trust labels are policy inputs.** `trust` on a Source is set by whoever registered it or
by tenant policy; Custody does not infer it. The certificate lists every reached root with
its label (`root_sources`) and says so (`trust_labels_note`), so a reviewer can audit the
assumption.

**Provenance coverage.** Every model-produced Datum (`llm_output`, `memory`, `message`,
`typed_value`) stores `coverage`:

| coverage | meaning |
|---|---|
| `FULL_CONTEXT` | `DERIVED_FROM` edges to everything in the producing call's context window (the Recorder contract; the default; `AgentSession` always records it). Exact-value attribution keeps every context edge (marked `context`), so it stays FULL_CONTEXT. |
| `REDUCED` | a narrower attribution was used (declare with `coverage="REDUCED"` on the Recorder or the HTTP API) |
| (missing) | older data: treated as REDUCED |

The certificate collects the coverage of every model output in the examined ancestry.
All FULL_CONTEXT → `strength: STRONG`. Otherwise `strength: DOWNGRADED`,
`provenance_coverage: REDUCED`, the offending Datums are listed (`reduced_provenance`) and
the claim states it is *not an exhaustive account of recorded influence*. The verdict does
not change: coverage qualifies the negative claim, it is not a policy check.

**Deterministic certificate id.** `certificate_id = "pcc_" + sha256(action, destination
ids, graph, graph version, ancestry digest, roots with trust label and status, coverage
and reduced Datums, policy name@version, payload outcome)[:16]` (the field names are in
`certificate_id_inputs`). The same action evaluated against the same graph state gives the
same id (recording a Decision does not move the version); a provenance write, a trust
label change or a coverage change gives a different one. It is a convenient fingerprint
for comparing and re-checking decisions, not a security proof. `id` stays a unique
issuance id. Tests: `tests/guard/test_certificate_coverage.py`. Not issued for REQUIRE_HUMAN_APPROVAL / BLOCK, for an ALLOW obtained by a human
approving a violating or unbound destination, or for unguarded action types. Tests:
`tests/guard/test_certificate.py`.

### Secret-egress endorsement

`Guard.endorse(ids, egress=True)` (API: `POST /guard/endorse {"egress": true}`) records
`(:Approval {egress:true})-[:ENDORSES {egress:true}]->(:Datum)`. The confidentiality check
(secret payload, external sink) is cleared only when **all** hold: integrity is not violated,
the destination is bound, and a complete search from the destination argument along
Guard-followed edges reaches a Datum whose fingerprint equals the sink's destination value
and that a human endorsed with `egress: true` (`Q.EGRESS_HIT`). An incomplete search clears
nothing. `CheckResult.cleared_by_endorsement` lists the approvals. Policy switch:
`GuardPolicy.egress_endorsements`.

### Precedent escalation

When the verdict would be REQUIRE_HUMAN_APPROVAL, the confidentiality check is violated
(secret payload to an external sink) and the action has a Sink, `Q.PRECEDENT` looks for
`(:Approval {verdict:'rejected'})-[:REJECTS]->(prev:Action)-[:TO]->(k:Sink)<-[:TO]-(current)`
where `prev` has a non-destination argument with `sensitivity: 'secret'` and the approver is
human. A match escalates to BLOCK (check `precedent`, no approval option) and the decision
carries each precedent with the exact relationship pattern and ids. Rejections of
non-secret actions, other sinks, and non-secret payloads never escalate.
`GuardPolicy.precedent_escalation` turns it off.

### Retroactive re-adjudication

`custody/guard/readjudicate.py`, `POST /guard/sources/{id}/revoke {approver, reason}`
(human only). The Source's `trust` becomes `untrusted` (`trust_original` keeps the old
label; a `(:TrustRevocation)-[:REVOKES]->(:Source)` records who/when/why). A complete
forward traversal (`traversal.search(..., reverse=True)`, every edge) from the Source's
Datums finds downstream memories, messages and actions; if it is incomplete the report is
refused (the revocation stays: fail closed). The current Guard re-checks each action
without writing a Decision or changing its status; the result is stored as
`(:TrustRevocation)-[:PRODUCED]->(:Readjudication)-[:READJUDICATES]->(:Action)` with the
original verdict (the last Decision recorded before the revocation) and the current one.

## Policy

| Result | Decision | Approval |
|---|---|---|
| no dangerous path | `ALLOW` | — |
| integrity **or** confidentiality | `REQUIRE_HUMAN_APPROVAL` | offered |
| lethal trifecta | `BLOCK` | **never offered** |
| action type has `human_review` (e.g. Warden's `send_disclosure`) and no human approved it | `REQUIRE_HUMAN_APPROVAL` (check `human_review`) | offered: `APPROVES {checks:['human_review']}`, this action only |

`ActionPolicy.human_review` (default `False`) is an opt-in per action type. It never
loosens anything: the provenance checks still run, and a lethal trifecta still BLOCKs.
`quarantine_memory` (Warden, internal, no sink) and `send_disclosure` (Warden, external
email, `human_review=True`) are registered in `DEFAULT_ACTIONS`. See [warden.md](warden.md).

`Guard.enforce` also moves `Action.status`: `approved`, `pending_approval` or `blocked`.
`blocked`, `rejected`, `executed` and `failed` are terminal.

## Sinks: internal vs external

The agent's declared `Sink.external` is advisory. The Guard re-classifies every sink and
fails closed:

- `email`: domain equals or is a subdomain of an internal domain (`acme-robotics.example`);
  look-alikes such as `acme-robotics.example.evil.example` are external.
- `slack`: workspace is internal (`acme-robotics`) and the channel is not a shared Slack
  Connect channel (`#ext-rivalbots-partners`).
- `backup` / `http` / `webhook`: http(s) URL whose host is internal.
- `ticket`: internal ticket system (`acme-jira`).
- anything else, unparseable destinations, or tenants without a policy: external.

## Human approval

| Violation | What `Guard.approve` records | Scope |
|---|---|---|
| integrity (bound destination) | `(:Approval)-[:ENDORSES]->(destination Datum)`, sets `endorsed = true` | that Datum and anything derived from it |
| integrity (unbound destination) | `(:Approval)-[:APPROVES {checks:['integrity']}]->(:Action)` | this action only |
| confidentiality | `(:Approval)-[:APPROVES {checks:['confidentiality']}]->(:Action)` | this action only (the secret is not declassified) |
| lethal trifecta | refused (`ApprovalRefused`, HTTP 403) | — |

The Guard re-runs after approving. The re-run sees the endorsed node on the path and
reports the path as `cleared` with the approval id.

Guardrails:
- Only `approver_kind = "human"` approvals count; agent or `system:` approvers are refused.
- The trifecta check ignores action-scoped approvals.
- `Guard.endorse` refuses any Datum on the destination provenance of a blocked action,
  so a blocked trifecta cannot be laundered by endorsing its inputs afterwards.
- Monotonicity: new Datums only point at older ones, so an existing action's ancestry
  never grows. Only explicit human approvals make a decision more permissive.

## Label-creep mitigation

**1. Exact-value attribution** (`custody/recorder/attribution.py`). The runtime records
each tool argument with `attribution="exact"`. If a *trusted* Datum in or behind the
context supplied that exact value, the argument gets one edge
`DERIVED_FROM {op:'attribute', attribution:'exact'}` to the supplier. The other context
items get `attribution:'context'` edges, which are kept for audit but not followed by the
Guard. Sensitivity is taken from the suppliers only.

- Exact means a whole-value fingerprint match (the only way secrets match, since their
  raw value is never stored) or a whole-token match in the supplier's text.
  `board@acme-robotics.example` does **not** match inside
  `board@acme-robotics.example.evil.example`.
- A supplier counts as trusted only if it has no uncleared path to an untrusted Source.
  This is the same traversal the Guard uses.
- If there is no trusted supplier, the argument falls back to normal inheritance.

**2. Internal destinations.** Secrets going to internal sinks such as Acme Slack
`#security` are reported as `info` paths and do not trigger confidentiality.

**3. Quarantined / typed reader** (`custody/recorder/quarantine.py`).
`Recorder.record_typed_value` (`AgentSession.extract_typed`) pulls a value out of
untrusted content and validates it deterministically against a narrow type: `int`,
`number`, `bool`, `date`, `enum`, `ticket_id` or `currency`. Free-form types (`email`,
`url`, `text`, ...) are refused. The value is stored as `:Datum:Typed` with
`quarantined = true`, `value_type` and `max_risk = 'low'`. An untrusted path that passes
through such a node is `limited`: it is allowed for low-risk actions such as
`update_ticket` and is still a violation for high-risk ones.

## Decision shape

`GuardDecision` (`custody/guard/models.py`) contains: `decision`, `triggered_checks`,
`action_id`, `explanation`, per-check `checks` (violated, raw_violation, detail, paths,
cleared_by_action_approval, latency_ms, query), `paths` (each with nodes, ops, sessions,
agents, status `violating | cleared | limited | info`, and a one-line `text`), `sources`,
`sink` (declared vs classified external, zone, reason, `bound`), `approval` (available,
reason, endorse_datum_ids, approve_checks), `latency_ms` (per query and total), `policy`
and `deterministic: true`.

Every evaluation is also appended to the graph as an audit record:
`(:Decision {decision, triggered, explanation, latency_ms, ...})-[:EVALUATES]->(:Action)`.

## Runtime integration

```python
rt = AgentRuntime(recorder, Guard(recorder, ACME_POLICY), vault=..., web=...)
s = rt.session("ops", "s3")
s.user("Rotate the AWS deploy key and post the new key to #security in Acme Slack.", user="sam")
s.rotate_secret("secret/aws/deploy-key")
res = s.call_tool("post_slack", destination="#security", payload=new_key)
# propose → Guard.enforce → ALLOW → execute → status executed
rt.approve(action_id, approver="sam")    # for REQUIRE_HUMAN_APPROVAL; re-checks, then executes
rt.execute(action_id)                    # always re-checks; raises ExecutionDenied unless ALLOW
```

## Demo

```bash
python scripts/guard_demo.py --embedded .data/custody.db
```

- **Safe case:** Sam asks to post the rotated key to `#security` in Acme Slack, while
  the untrusted vendor memory is also in context. The destination is attributed to Sam
  and the sink is internal, so the result is **ALLOW** and the key is posted.
- **Dangerous case:** the vendor page plants
  `https://ingest.vaultsync-mirror.example/v1/upload`. It flows into a memory and a
  message in session 1, then the ops agent proposes `upload_backup` with the vault key in
  session 2. The result is **BLOCK** (lethal trifecta), with two provenance paths
  (through the message and through shared memory), no approval option and nothing
  executed.

## HTTP

| Method | Path | |
|---|---|---|
| POST | `/tenants/{t}/guard/actions/{id}/check?enforce=false` | decision (optionally update status) |
| POST | `/tenants/{t}/guard/actions/{id}/approve` `{approver, reason}` | apply allowed approval, re-check; 403 for trifecta |
| POST | `/tenants/{t}/guard/actions/{id}/reject` | mark rejected |
| POST | `/tenants/{t}/guard/endorse` `{approver, datum_ids}` | data-level endorsement; 403 if it feeds a blocked action |
| GET | `/tenants/{t}/guard/actions/{id}/decisions` | audit trail |
