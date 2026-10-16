# Custody Guard

The Guard decides whether an agent's outbound or irreversible action may run. It is
**deterministic**: no LLM is consulted. Each decision is a pure function of

1. **graph facts**: complete reachability searches over the provenance graph
   (`custody/graph/traversal.py`) plus a few Cypher queries for evidence paths, destination
   binding and precedent (`custody/guard/queries.py`);
2. the tenant's static **`GuardPolicy`** (`custody/guard/policy.py`): which actions are
   guarded, which destinations are internal, search limits;
3. the **Source trust labels**, which are policy inputs set by whoever registered the Source
   (or by tenant policy). Custody does not infer them.

Code: `custody/guard/` (Guard, policy, queries, models, certificate, contamination,
re-adjudication), `custody/runtime/` (the agent runtime that enforces verdicts),
`custody/api/routes/guard.py` (HTTP). Quick links: [checks](#checks),
[completeness](#completeness-path_found--no_path--indeterminate),
[certificate](#provenance-completeness-certificate), [approvals](#human-approval),
[HTTP](#http).

## Threat model

In scope: **explicit data flow that the runtime records**. Every user message, web page,
tool output, vault read, LLM output, memory, recall and inter-agent message is a `Datum`
with `DERIVED_FROM` edges to what produced it. An attacker controls the content of
untrusted Sources (web pages, inbound email, ...) and can make a model write anything into
memory or tool arguments.

Out of scope: **implicit flows through the model's internal reasoning.** If an untrusted
page convinces the model to *choose* one trusted value over another (e.g. pick `#security`
over `#general`, both typed by the user), the graph sees a value the user supplied and the
Guard treats it as trusted. Timing and other side channels are out of scope too.
Exact-value attribution relies on this boundary on purpose.

Assumptions: the runtime records context faithfully (each model output is linked to every
Datum that was in its context window; see "Provenance coverage" below); Source trust labels
are correct inputs; approvers are humans authenticated outside Custody.

## Checks

Run for every action whose policy is outbound or irreversible (unknown action types are
treated as outbound, irreversible and high risk). Unguarded types (e.g. `read_file`) are
allowed without checks and get no certificate.

| Check | Fires when |
|---|---|
| **Integrity** | a destination argument has an uncleared path to an untrusted Source (cleared = an endorsed Datum on it, or a typed value whose `max_risk` covers the action), the search could not finish, **or** the sink's literal destination is not bound to any recorded destination Datum |
| **Confidentiality** | a non-destination argument (payload) derives from a Datum with `sensitivity = 'secret'` (or the search could not finish) **and** the sink is external |
| **Lethal trifecta** | integrity violated **and** payload secret **and** sink external |
| **Human review** | the action type's policy has `human_review` (Warden disclosures, security-loosening remediations) and no human has approved it |
| **Precedent** | see [Precedent escalation](#precedent-escalation) |

## Policy result

| Result | Verdict | Approval |
|---|---|---|
| no check fires | `ALLOW` | — |
| integrity, confidentiality or human review | `REQUIRE_HUMAN_APPROVAL` | offered (see [Human approval](#human-approval)) |
| a search was INDETERMINATE (and no trifecta) | `REQUIRE_HUMAN_APPROVAL` | **not offered**: nothing concrete to approve; a later complete re-check decides |
| lethal trifecta (or one that cannot be ruled out) | `BLOCK` | **never** (HTTP 403) |
| precedent escalation | `BLOCK` | never |

The verdict enum is `ALLOW`, `REQUIRE_HUMAN_APPROVAL`, `BLOCK` everywhere (HTTP, Decision
nodes, re-adjudication, `why_allowed`). Only the MCP `check_action` / `explain_decision`
results abbreviate it to `REQUIRE_APPROVAL`.

`Guard.enforce` also moves `Action.status`: `approved`, `pending_approval` or `blocked`.
`blocked`, `rejected`, `executed` and `failed` are terminal.

## Completeness: PATH_FOUND / NO_PATH / INDETERMINATE

The verdict for integrity and confidentiality comes from a **complete** reachability search
(`traversal.untrusted_origin` / `secret_origin`): a level-by-level BFS with a visited set
(cycle-safe, each node expanded once, **no depth bound** by default), one read-only query
per level, applying the Guard's edge and node rules (skip `attribution: "context"` edges;
stop at endorsed Datums and, for integrity, at typed values that cover the action's risk):

```cypher
UNWIND $ids AS i MATCH (n:Datum {id: i}) WITH n
MATCH (n)-[r:DERIVED_FROM]->(m:Datum)
WHERE coalesce(r.attribution,'inherit') <> 'context' AND coalesce(m.endorsed,false) = false
RETURN DISTINCT n.id, m.id, r.op, size([(m)-[:FROM]->(s:Source {trust:'untrusted'}) | s.id]) > 0
```

| Outcome | Meaning | Treated as |
|---|---|---|
| `PATH_FOUND` | a relevant path exists (witness path attached) | violation |
| `NO_PATH` | the traversal exhausted the reachable graph | clean |
| `INDETERMINATE` | did not finish: `depth_limit`, `node_limit`, `timeout`, `query_error` | **violation (fail closed)** |

A check passes only when `path_found = false` **and** `search_complete = true`. An
INDETERMINATE result never yields ALLOW (the Guard raises `RuntimeError` rather than
return one), never offers an approval, is not cleared by action-scoped approvals, and makes
a trifecta that cannot be ruled out a BLOCK. (Known edge case: a secret-egress endorsement
does not itself check that the confidentiality search completed; if it would clear an
INDETERMINATE confidentiality search, that last-line assertion turns the check into an
error instead of an ALLOW. See [Secret-egress endorsement](#secret-egress-endorsement).)

**Evidence queries.** The UI and explanations also need concrete paths. A variable-length
pattern (`integrity_paths` / `confidentiality_paths`, `*0..25`, i.e. `GuardPolicy.max_depth`)
enumerates paths with a 250 ms server timeout (`evidence_timeout_ms`), worst paths first
(uncleared, then not typed, then shortest). It can only *confirm* a violation: if it returns
a violating path, that path is real and is used as the PATH_FOUND witness (the BFS is then
skipped, `method = "bounded_paths"`); if it returns nothing, times out or fails, the
complete BFS decides. "No path within 25 hops" is never taken as clean. Path enumeration
is exponential on dense DAGs (a multi-turn session where every output derives from every
earlier one has ≈2^t paths), which is why it is bounded and only used this way.

**Any route, not the shortest.** The verdict asks whether *any* uncleared route exists.
The route shown is the shortest uncleared one, labelled as evidence. Length is never an
input. Tests: `tests/guard/test_any_route.py`, `tests/guard/test_trace_completeness.py`.

**Distinct roots and route independence** (`custody/guard/contamination.py`, explanation
only, after a violating integrity verdict): every distinct untrusted root (one BFS, "at
least N" if it hits its budget), one shortest route per root, and `independence` ∈
`independent` (two routes sharing no Datum after the argument were found, or no single
Datum lies on every route: Menger), `converging` (a Datum on every route, verified),
`direct` (the argument itself is untrusted content), `unverified` (budget or incomplete
search). Budget: `contamination_timeout_ms` (1 s), `contamination_max_checks` (25). It
never changes the verdict.

Limits: `GuardPolicy.search_max_depth` (default `None` = unbounded), `search_max_nodes`
(100 000), `search_timeout_ms` (2 000; also the per-query server timeout). Cost: about
0.6–0.8 ms per BFS level on embedded FalkorDB (scaling and large-graph runs); a found path stops early. Measured in
[bench/README.md](../bench/README.md), including where the shipped limits make large
graphs fail closed.

## Provenance Completeness Certificate

An ALLOW from the provenance checks carries `GuardDecision.certificate`
(`ProvenanceCertificate`), or `certificate_unavailable` with the reason. It builds on the
verdict's search; it does not replace it.

1. The integrity search must be a complete `NO_PATH` (termination `exhausted`). Its visited
   set is the set of nodes on Guard-followed paths.
2. A second traversal (`traversal.ancestor_graph`) walks the **complete recorded ancestor
   graph** of the destination argument(s): every `DERIVED_FROM` edge, including the
   `context` edges, then reads the `FROM` Source of every Datum reached. If it is not
   exhausted, there is no certificate (the ALLOW still rests on step 1).
3. Each reached Source is listed with its trust label and a status: `followed` (on a
   Guard-followed path; never untrusted for an ALLOW, checked), `context_only` (reached
   only via context edges: exact-value attribution found a trusted supplier) or `cleared`
   (every followed path passes through human-endorsed or typed data).
4. The graph version is read before and after (`GraphMeta.started/finished`, which count
   provenance writes, action-status changes, approvals, quarantines and revocations;
   Decision and Run records don't count). The certificate requires no write in flight and
   no change during the check, and records `graph@vN` plus
   `ancestry_digest = sha256(examined nodes + flags, edges + attribution, FROM sources)`.

**The claim** begins, verbatim: *"No untrusted influence was found relative to the
recorded provenance graph (graph version V) and current Source trust labels."* It covers
the recorded graph only (unrecorded influence such as implicit flows is outside it) and
says explicitly that it does not say the action is safe.

**Trust labels are policy inputs.** The certificate lists every reached root with its label
(`root_sources`) and says so (`trust_labels_note`), so a reviewer can audit the assumption.

**Provenance coverage.** Every model-produced Datum (`llm_output`, `memory`, `message`,
`typed_value`) stores `coverage`:

| coverage | meaning |
|---|---|
| `FULL_CONTEXT` | `DERIVED_FROM` edges to everything in the producing call's context window (the Recorder contract and default; `AgentSession` always records it). Exact-value attribution keeps every context edge (marked `context`), so it stays FULL_CONTEXT. |
| `REDUCED` | a narrower attribution was used (declared with `coverage="REDUCED"` on the Recorder or HTTP API) |
| (missing) | older data: treated as REDUCED |

All FULL_CONTEXT in the examined ancestry → `strength: STRONG`. Otherwise
`strength: DOWNGRADED`, `provenance_coverage: REDUCED`, the Datums are listed
(`reduced_provenance`) and the claim says it is *not an exhaustive account of recorded
influence*. Coverage qualifies the claim; it does not change the verdict.

**Deterministic certificate id.** `certificate_id = "pcc_" + sha256(action, destination
ids, graph, graph version, ancestry digest, roots with trust label and status, coverage and
reduced Datums, policy name@version, payload outcome)[:16]` (`certificate_id_inputs` lists
the fields). The same action against the same graph state gives the same id; any write
that moves the graph version (including the runtime marking the action executed), a trust
label change or a coverage change gives a different one. It is a fingerprint for comparing
re-checks, not a proof. `id` stays a unique issuance id.

**Not issued** for REQUIRE_HUMAN_APPROVAL / BLOCK; for an ALLOW obtained through an
action-scoped approval of the integrity check (an unbound destination: there is no
negative claim to make); for actions without a destination argument (e.g. Warden
remediations: nothing to certify); for unguarded action types; when either traversal was
incomplete, the graph changed during the check, or the evidence was inconsistent. An ALLOW
reached through an endorsement (a cleared root) or a confidentiality approval / egress
endorsement is certified, with the clearance listed.

Tests: `tests/guard/test_certificate.py`, `tests/guard/test_certificate_coverage.py`.
The Warden's `why_allowed` renders a certificate as fixed-template text.

## Human approval

| Violation | What `Guard.approve` records | Scope |
|---|---|---|
| integrity (bound destination) | `(:Approval)-[:ENDORSES]->(destination Datum)`, sets `endorsed = true` | that Datum and anything derived from it |
| integrity (unbound destination) | `(:Approval)-[:APPROVES {checks:['integrity']}]->(:Action)` | this action only |
| confidentiality | `(:Approval)-[:APPROVES {checks:['confidentiality']}]->(:Action)` | this action only (the secret is not declassified) |
| human review | `(:Approval)-[:APPROVES {checks:['human_review']}]->(:Action)` | this action only |
| lethal trifecta, precedent, incomplete search | refused (`ApprovalRefused`, HTTP 403) | — |

The Guard re-runs after approving; the re-run sees the endorsed node and reports the path as
`cleared` with the approval id. Rejection records `(:Approval {verdict:'rejected'})-[:REJECTS]->(:Action)`.

Guardrails (in `Guard.approve` / `Guard.endorse`):
- Only human approvers count: `approver_kind` must be `human` and the approver must not be a
  `system:` principal. (The Warden's own wrappers additionally refuse the name `warden`.)
- The trifecta check ignores action-scoped approvals.
- `Guard.endorse` refuses any Datum on the destination provenance of a blocked action
  (complete search; an incomplete search refuses), so a blocked trifecta cannot be
  laundered by endorsing its inputs afterwards.

> **Recorder write API is trusted-integrator only.** `POST /tenants/{t}/record/approval`
> and `PATCH /tenants/{t}/actions/{id}/status` write approvals and statuses directly,
> without these guardrails (they exist for integrations that record decisions made
> elsewhere). Do not expose the Recorder routes to untrusted callers; public-demo mode
> blocks them.

### Secret-egress endorsement

`Guard.endorse(ids, egress=True)` (HTTP: `POST /guard/endorse {"egress": true}`) records
`(:Approval {egress:true})-[:ENDORSES {egress:true}]->(:Datum)`. It clears the
confidentiality check only when **all** hold: integrity is not violated, the destination is
bound, and a complete search from the destination argument along Guard-followed edges
reaches a Datum whose fingerprint equals the sink's destination value and that a human
endorsed with `egress: true`. The current code does not additionally require the
confidentiality search itself to have completed: in the rare case where it was
INDETERMINATE and an egress endorsement applies, the Guard's final fail-closed assertion
raises an error (HTTP 500) instead of returning ALLOW. A one-line fix (skip the endorsement
when the confidentiality search is indeterminate) is pending.
`CheckResult.cleared_by_endorsement` lists the approvals. Switch:
`GuardPolicy.egress_endorsements`. (World A of the three-worlds demo uses it.)

### Precedent escalation

When the verdict would be REQUIRE_HUMAN_APPROVAL, the confidentiality check is violated
with a complete search (secret payload to an external sink) and the action has a Sink,
`Q.PRECEDENT` looks for
`(:Approval {verdict:'rejected'})-[:REJECTS]->(prev:Action)-[:TO]->(k:Sink)<-[:TO]-(current)`
where `prev` had a secret non-destination argument and the approver was human. A match
escalates to BLOCK (check `precedent`, no approval option) and cites the exact relationship
and ids. Switch: `GuardPolicy.precedent_escalation`.

### Retroactive re-adjudication

`custody/guard/readjudicate.py`; `POST /guard/sources/{id}/revoke {approver, reason}`
(human only), or the Warden's Guard-checked `revoke_source_trust` action. The Source's
`trust` becomes `untrusted` (`trust_original` keeps the old label;
`(:TrustRevocation)-[:REVOKES]->(:Source)` records who/when/why). A complete forward
traversal from the Source's Datums finds downstream memories, messages and actions; if it is
incomplete the report is refused (the revocation stays: fail closed). The current Guard
re-checks each action without writing a Decision or changing its status; results are stored
as `(:TrustRevocation)-[:PRODUCED]->(:Readjudication)-[:READJUDICATES]->(:Action)` with the
original verdict (last Decision before the revocation) and the current one
(`ALLOW → BLOCK`, `ALLOW → REQUIRE_HUMAN_APPROVAL`, `UNCHANGED`, ...). Recorded Decisions,
statuses and executions are not changed. `GET /guard/readjudications` lists reports.

### What can change a later re-check

Provenance is append-only and new Datums only point at older ones, so an existing Datum's
ancestry never grows. A re-check can still differ after: human endorsements or approvals
(more permissive), trust revocations, rejections that set a precedent, or a policy change
(stricter), and human-approved trust restorations or quarantine lifts. Agent activity alone
never makes a decision more permissive.

## Policy configuration

`ActionPolicy(outbound, irreversible, risk, human_review)` per action type in
`DEFAULT_ACTIONS`. Warden types: `quarantine_memory` and `revoke_source_trust`
(internal, low risk: tightening), `send_disclosure` (external email, `human_review`),
`unquarantine_memory`, `endorse_data`, `restore_source_trust`, `weaken_restriction`
(`human_review`: loosening). See [warden.md](warden.md#asymmetric-remediation-custodywardenremediationpy).
`human_review` never loosens anything: the provenance checks still run.

## Sinks: internal vs external

The agent's declared `Sink.external` is advisory. The Guard re-classifies every sink and
fails closed:

- `email`: domain equals or is a subdomain of an internal domain (`acme-robotics.example`);
  look-alikes such as `acme-robotics.example.evil.example` are external.
- `slack`: workspace is internal (`acme-robotics`) and the channel is not a shared Slack
  Connect channel (`#ext-rivalbots-partners`).
- URL kinds (`http`, `https`, `url`, `webhook`, `backup`, `upload_backup`, `http_post`,
  `configure_backup`): an http(s) URL whose host is internal.
- `ticket`: internal ticket system (`acme-jira`).
- anything else, unparseable destinations, or tenants without a policy: external.

Secrets going to internal sinks (Acme Slack `#security`) are reported as `info` paths and do
not trigger confidentiality.

## Label-creep mitigation

**Exact-value attribution** (`custody/recorder/attribution.py`). The runtime records each
tool argument with `attribution="exact"`. If a *trusted* Datum in or behind the context
supplied that exact value, the argument gets one edge
`DERIVED_FROM {op:'attribute', attribution:'exact'}` to the supplier; the other context
items get `attribution:'context'` edges, kept for audit (and walked by the certificate) but
not followed by the verdict search. Sensitivity is taken from the suppliers only.

- Exact = a whole-value fingerprint match (the only way secrets match) or a whole-token
  match in the supplier's text (`board@acme-robotics.example` does **not** match inside
  `board@acme-robotics.example.evil.example`).
- Candidate suppliers are looked up within `CUSTODY_MAX_TRACE_DEPTH` hops (default 25). A
  candidate counts as trusted only if the complete BFS proves it has no uncleared path to
  an untrusted Source (stricter than the Guard: typed values do not clear it).
- No trusted supplier → normal inheritance (the conservative default).

**Quarantined / typed reader** (`custody/recorder/quarantine.py`).
`Recorder.record_typed_value` (`AgentSession.extract_typed`) validates a value pulled out of
untrusted content against a narrow type (`int`, `number`, `bool`, `date`, `enum`,
`ticket_id`, `currency`; free-form types are refused) and stores it as `:Datum:Typed` with
`quarantined = true`, `value_type` and `max_risk` (default `low`). An untrusted path through
it is `limited`: allowed for actions whose risk tier `max_risk` covers, a violation otherwise.

## Decision shape

`GuardDecision` (`custody/guard/models.py`): `decision`, `triggered_checks`, `explanation`,
per-check `checks` (violated, raw_violation, detail, paths, `search` outcome,
cleared_by_action_approval, cleared_by_endorsement, precedents, latency_ms, query), `paths`
(nodes, ops, sessions, agents, status `violating | cleared | limited | info`, text),
`sources`, `sink` (declared vs classified, zone, reason, `bound`), `approval` (available,
reason, endorse_datum_ids, approve_checks), `latency_ms`, `policy`, `search_complete`,
`indeterminate_checks`, `certificate` / `certificate_unavailable`, `contamination`,
`deterministic: true`. Each evaluation is appended as
`(:Decision {...})-[:EVALUATES]->(:Action)` (unless `record_decisions=False`).

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

`python scripts/guard_demo.py --embedded .data/custody.db` runs an allowed case (ALLOW: Sam's
`#security`, internal) and a dangerous case (BLOCK: `upload_backup` to a planted URL with
the vault key, reached through a message and through shared memory).

## HTTP

All under `/api/tenants/{t}/guard` (the routes are also mounted without `/api`).

| Method | Path | Body | |
|---|---|---|---|
| POST | `/actions/{id}/check?enforce=false` | — | decision (optionally update status) |
| POST | `/actions/{id}/approve` | `{approver, reason}` | apply the offered approval, re-check; 403 if refused |
| POST | `/actions/{id}/reject` | `{approver, reason}` | record a rejection (`REJECTS`), status `rejected` |
| POST | `/endorse` | `{approver, datum_ids, reason, egress}` | data-level endorsement; 403 if it feeds a blocked action |
| POST | `/sources/{id}/revoke` | `{approver, reason}` | trust revocation + re-adjudication report |
| GET | `/readjudications?limit=10` | — | stored re-adjudication reports |
| GET | `/actions/{id}/decisions` | — | audit trail |
