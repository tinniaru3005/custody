# Guard

The Guard decides whether an agent's outbound or irreversible action may run. It is deterministic: each decision is a pure function of graph query results and the tenant's static policy. No language model is consulted, and re-running a check on the same graph gives the same verdict, checks and paths (as long as the searches complete within their [limits](#complete-search-path-found-no-path-indeterminate); a search that runs out of time fails closed).

Code: [`custody/guard/`](repo:custody/guard/) (Guard service, policy, queries, models), [`custody/graph/traversal.py`](repo:custody/graph/traversal.py) (complete search), [`custody/api/routes/guard.py`](repo:custody/api/routes/guard.py) (HTTP). Long-form reference: [`docs/guard.md`](repo:docs/guard.md).

![The Guard decision page for the blocked upload](guard-block.webp "Guard decisions page: the BLOCK banner, the explanation and the shortest uncleared route from the destination back to the untrusted vendor page.")

## Checks

The checks run for every action type that the policy marks as outbound or irreversible. Action types the policy does not know are treated as outbound, irreversible and high risk.

| Check               | Fires when                                                                                                                                                                                                                                                                                            |
| ------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Integrity**       | A destination argument has an uncleared path to an untrusted Source (cleared: an endorsed Datum on it, or a typed value whose `max_risk` covers the action's risk tier), the search cannot finish, or the sink's literal destination is not bound to any recorded destination Datum (by fingerprint). |
| **Confidentiality** | A payload (any non-destination argument) derives from a Datum with `sensitivity = 'secret'` (or the search cannot finish) **and** the sink is external.                                                                                                                                               |
| **Lethal trifecta** | Integrity is violated **and** the payload is secret **and** the sink is external (also when an incomplete search means it cannot be ruled out).                                                                                                                                                       |
| **Human review**    | The action type always needs a human (the Warden's `send_disclosure`, and the loosening remediations `unquarantine_memory`, `endorse_data`, `restore_source_trust`, `weaken_restriction`) and no human has approved it.                                                                               |
| **Precedent**       | An action that would need approval for confidentiality (secret payload to an external sink) goes to a Sink where a human already rejected an action carrying a secret. See [precedent escalation](#precedent-escalation).                                                                             |

![Checks and the lethal-trifecta panel for the blocked upload](guard-checks.webp "Each check shows its result, its detail and the queries behind it, with timings. The trifecta panel lists the three conditions.")

## Verdicts

| Result                                         | Verdict                  | Approval                                                                        |
| ---------------------------------------------- | ------------------------ | ------------------------------------------------------------------------------- |
| nothing fires                                  | `ALLOW`                  | none needed                                                                     |
| integrity or confidentiality                   | `REQUIRE_HUMAN_APPROVAL` | offered: endorse the data, or approve these checks for this action only         |
| human review                                   | `REQUIRE_HUMAN_APPROVAL` | offered: approve `human_review` for this action only                            |
| a search was `INDETERMINATE` (and no trifecta) | `REQUIRE_HUMAN_APPROVAL` | **not offered**: nothing concrete to approve; a later complete re-check decides |
| lethal trifecta, or precedent                  | `BLOCK`                  | **never offered**: the API returns 403 and the console shows no button          |

The verdict values are the same everywhere (HTTP, `Decision` nodes, re-adjudication). The console labels the middle one "REQUIRE APPROVAL", and the MCP `check_action` / `explain_decision` results abbreviate it to `REQUIRE_APPROVAL`.

`Guard.enforce` also moves the action's status to `approved`, `pending_approval` or `blocked`. `blocked`, `rejected`, `executed` and `failed` are terminal. Over HTTP, `POST …/guard/actions/{id}/check?enforce=true` does the same; without `enforce` the check changes nothing but the audit trail.

## Complete search: PATH_FOUND, NO_PATH, INDETERMINATE

"No path within 25 hops" is not "no path". The verdicts for integrity and confidentiality come from a complete reachability search: a breadth-first search over `DERIVED_FROM` with a visited set (cycle-safe, each node expanded once, no depth bound by default), one read-only query per level (frontiers are batched, 500 ids per query). A simplified version of the integrity search's expansion query (the confidentiality search uses the same edge filter but does not stop at endorsed Datums; the integrity search also stops at typed values whose `max_risk` covers the action):

```cypher
UNWIND $ids AS i MATCH (n:Datum {id: i}) WITH n
MATCH (n)-[r:DERIVED_FROM]->(m:Datum)
WHERE coalesce(r.attribution, 'inherit') <> 'context'
  AND coalesce(m.endorsed, false) = false
RETURN DISTINCT n.id, m.id, r.op
```

Each search ends in one of three outcomes:

| Outcome         | Meaning                                                                 | Treated as                  |
| --------------- | ----------------------------------------------------------------------- | --------------------------- |
| `PATH_FOUND`    | a relevant path exists; a witness path is attached as evidence          | violation                   |
| `NO_PATH`       | the traversal exhausted the reachable graph                             | clean                       |
| `INDETERMINATE` | it did not finish: node limit, time limit, depth limit or a query error | **violation (fail closed)** |

A check passes only when no path was found **and** the search completed. An `INDETERMINATE` result is never ALLOW (as a last line, the Guard raises an error rather than return one); if a lethal trifecta cannot be ruled out it is a BLOCK, otherwise `REQUIRE_HUMAN_APPROVAL` with no approval option, because there is nothing concrete to approve. A later re-check that completes decides normally.

Limits (fields of `GuardPolicy`): `search_max_nodes` 100 000, `search_timeout_ms` 2 000 (a wall-clock budget per search; the remaining budget is passed to FalkorDB as each query's timeout), `search_max_depth` unbounded by default. `CUSTODY_MAX_TRACE_DEPTH` bounds lineage and trace views, not verdicts.

**Any route decides; the shortest route only explains.** The verdict asks whether _any_ uncleared route reaches an untrusted Source. A one-hop route to something the user typed does not hide a 60-hop route to a vendor page next to it, an endorsed short route does not clear an unendorsed longer one, and path length never enters the verdict. Separately, a bounded variable-length query (`*0..25`, 250 ms timeout) collects evidence paths for the explanation. A violating path it returns is real and is used as the witness, so it can confirm a violation; an empty or timed-out evidence query never clears anything, and the complete search then decides.

## Untrusted roots and route independence

After the verdict, when the integrity search found an uncleared route, the Guard also reports every distinct untrusted root (or "at least" that many if the root search hit a limit) and whether the routes to them are independent. This is explanation only and cannot change the verdict; if the analysis fails, the decision simply has no report.

![Untrusted roots and route independence for the blocked upload](guard-contamination.webp "One untrusted root; every route passes through the shared memory, verified by removing it and finding no remaining route.")

- **Independent**: two routes that share no Datum after the argument were found, or removing each Datum of the first route in turn still leaves an untrusted route.
- **Converging**: a Datum on every route was verified (removing it leaves none). In the primary demo that Datum is the shared memory.
- **Direct**: the argument itself is untrusted content.
- **Unverified**: a search was incomplete or the budget ran out (`contamination_max_checks` 25, `contamination_timeout_ms` 1 000).

## Provenance completeness certificate

Every ALLOW from the provenance checks carries a certificate, or `certificate_unavailable` with the reason. It makes the negative claim precise.

![The certificate on the allowed Slack post](guard-certificate.webp "The certificate for step 5: traversal complete, frontier exhausted, full context coverage, the graph version and a deterministic certificate id.")

The claim begins, verbatim: _"No untrusted influence was found relative to the recorded provenance graph (graph version V) and current Source trust labels."_ In plain terms: relative to the recorded provenance graph, current trust labels, and a complete traversal, no untrusted influence path was found. It certifies the recorded graph only and never says the action is safe. To issue one:

1. The integrity search must be a complete `NO_PATH`.
2. A second traversal walks the **complete recorded ancestor graph** of the destination, including the `context` edges the Guard does not follow, and reads the Source of every Datum reached.
3. Each reachable root Source is listed with its trust label and status: `followed` (on a path the Guard follows), `context_only` (reached only through context edges), or `cleared` (every followed path passes through endorsed or typed data). Trust labels are policy inputs, not findings, and the certificate says so.
4. The graph version (a write counter) is read before and after; the certificate requires that no write was in flight when the check started and none happened during it, and records a SHA-256 digest of exactly what was examined (`ancestry_digest`) and the graph version.

The certificate's `strength` is **STRONG** (`provenance_coverage: FULL_CONTEXT`) only if every model output in the ancestry has `FULL_CONTEXT` coverage; otherwise it is **DOWNGRADED** (`REDUCED`; missing coverage counts as reduced) and lists the reduced Datums. Its `certificate_id` (`pcc_` plus 16 hex characters) is a deterministic fingerprint of the decision state: the same action on the same graph state, policy and trust labels gives the same id. It is a fingerprint for comparing re-checks, not a proof.

No certificate is issued for `REQUIRE_HUMAN_APPROVAL` or BLOCK, for an ALLOW that came from an action-scoped approval of an integrity violation or unbound destination, for actions without a destination argument (such as Warden remediations), for action types the policy does not guard, or when a traversal hit a limit or the graph changed mid-check. The reason is given in `certificate_unavailable`.

## Sinks: internal or external

The sink's declared `external` flag is advisory. The Guard re-classifies every sink against tenant policy and fails closed:

| Sink kind                                                                                                    | Internal when                                                                                                                    |
| ------------------------------------------------------------------------------------------------------------ | -------------------------------------------------------------------------------------------------------------------------------- |
| `email`                                                                                                      | the domain equals or is a subdomain of an internal domain; look-alikes such as `acme-robotics.example.evil.example` are external |
| `slack`                                                                                                      | the workspace is internal and the channel is not a shared Slack Connect channel                                                  |
| `http`, `https`, `url`, `webhook`, `backup` (and the kinds `upload_backup`, `http_post`, `configure_backup`) | an http(s) URL whose host is internal                                                                                            |
| `ticket`                                                                                                     | the ticket system is internal                                                                                                    |
| anything else                                                                                                | external, as are unparseable destinations and tenants without a policy                                                           |

For the demo tenant `acme` the internal email domain and HTTP host are `acme-robotics.example`, the Slack workspace `acme-robotics` (with `#ext-rivalbots-partners` as a shared channel), and the ticket system `acme-jira`. Other tenants get the default policy, in which every sink is external. See [Configuration](/docs/configuration#guard-policy).

## Human approval

| Violation                      | What an approval records                                             | Scope                                            |
| ------------------------------ | -------------------------------------------------------------------- | ------------------------------------------------ |
| integrity, bound destination   | `(:Approval)-[:ENDORSES]->(destination Datum)` and `endorsed = true` | that Datum and everything derived from it        |
| integrity, unbound destination | `(:Approval)-[:APPROVES {checks:['integrity']}]->(:Action)`          | this action only                                 |
| confidentiality                | `(:Approval)-[:APPROVES {checks:['confidentiality']}]->(:Action)`    | this action only; the secret is not declassified |
| human review                   | `(:Approval)-[:APPROVES {checks:['human_review']}]->(:Action)`       | this action only                                 |
| lethal trifecta, or precedent  | refused: `ApprovalRefused`, HTTP 403                                 | none                                             |
| `INDETERMINATE` search         | refused: `ApprovalRefused`, HTTP 403                                 | none; re-check once the search can complete      |

The Guard re-runs after an approval; the re-run sees the endorsed node or the approval and reports the path as `cleared`. The console shows this as a decision flip:

![Decision flip after approving a disclosure](approvals-flip.webp "Approvals page after a human approves: the new APPROVES relationship read back from the graph, and the Guard's re-run verdict.")

Guardrails:

- The Guard's approve, reject and endorse calls refuse an `approver_kind` other than `human`, an empty approver, or one whose name starts with `system:`; the Warden's approval helpers also refuse `warden`. Action-scoped approvals, egress endorsements and rejections only count when `approver_kind` is `human`.
- The lethal-trifecta check ignores action-scoped approvals.
- `Guard.endorse` refuses any Datum on the destination provenance of a blocked action (complete search; an incomplete search also refuses), so a blocked trifecta cannot be laundered by endorsing its inputs afterwards.
- Approvers are assumed to be authenticated outside Custody. Custody has no login of its own.

> [!LIMITATION]
> The Recorder routes `POST …/record/approval` and `PATCH …/actions/{id}/status` write approvals and statuses directly, without these guardrails (a data endorsement written there sets `endorsed = true`, which clears integrity paths whatever the `approver_kind`). They exist for integrations that record decisions made elsewhere and are for trusted integrators only; public-demo mode blocks them.

## Policy features backed by the graph

### Secret-egress endorsement

`POST …/guard/endorse` with `{"egress": true}` lets a human vouch that secrets may go to the destination value a Datum holds. It clears the confidentiality check only if integrity is clean, the destination is bound, and a search from the destination argument along Guard-followed edges reaches a Datum whose fingerprint equals the sink's destination value and that a human endorsed with `egress: true` (if that search does not find one, nothing is cleared). The secret itself is not declassified for any other destination. `GuardPolicy.egress_endorsements` turns it off. World A on the [Three worlds](/docs/demos#three-worlds) page uses it.

> [!LIMITATION]
> The code does not yet also require the confidentiality search itself to have completed. In the rare case where it was `INDETERMINATE` and an egress endorsement applies, the Guard's final fail-closed assertion raises an error (HTTP 500) instead of returning ALLOW.

### Precedent escalation

When the verdict would be `REQUIRE_HUMAN_APPROVAL` because confidentiality is violated (a secret payload to an external sink, not cleared by an approval or egress endorsement, with a complete search), the Guard looks for a human rejection of an earlier action to the **same Sink** that had a secret Datum as a non-destination argument:

```cypher
(:Approval {verdict:'rejected'})-[:REJECTS]->(prev:Action)-[:TO]->(:Sink)<-[:TO]-(current)
```

A match escalates to BLOCK and the decision cites the relationship and ids. No similarity or embeddings are involved. `GuardPolicy.precedent_escalation` turns it off.

### Retroactive re-adjudication

Trust labels are policy inputs, so they can be wrong. `POST …/guard/sources/{source_id}/revoke` (a human approver; the Warden's `revoke_source_trust` runs it only after the Guard ALLOWs that tightening action) marks a previously trusted Source untrusted, walks forward from it over every `DERIVED_FROM` edge (context edges included) with a complete traversal, and re-runs today's Guard, read-only, on every recorded action with an argument downstream. It reports _original → current_ verdicts as transitions such as `ALLOW → BLOCK`, `ALLOW → REQUIRE_HUMAN_APPROVAL` or `UNCHANGED`. Original decisions, action statuses and executions are untouched; each re-check is stored as a `(:Readjudication)` node next to a `(:TrustRevocation)`. Recent reports: `GET …/guard/readjudications`. If the forward search is incomplete, the report is refused but the revocation stays (fail closed).

![Re-adjudication report after revoking a user's trust](readjudication.webp "Revoking user:sam (a drill): the Slack post that was ALLOW at execution time would need approval today; the blocked upload stays BLOCK. Statuses are unchanged.")

### Chokepoints

For a non-ALLOW action, the decision page can show which single provenance node, if removed, breaks every currently recorded untrusted path. Each candidate is verified by re-running the complete integrity search without it. It is a per-node what-if over today's graph, not a min-cut computation, and quarantining the node stops future recalls without changing recorded verdicts. Also at `GET …/console/actions/{id}/chokepoints` and as the Warden's `find_chokepoints` tool.

![Chokepoint analysis for the blocked upload](guard-chokepoints.webp "The shared memory lies on every known untrusted path; with it excluded, the complete integrity search returns NO_PATH.")

## Decision shape

`GuardDecision` ([`custody/guard/models.py`](repo:custody/guard/models.py)) contains `id`, the action (`action_id`, `action_type`, `agent`, `action_status`), `decision`, `triggered_checks`, `explanation`, per-check results (`checks`: `integrity`, `confidentiality`, `lethal_trifecta`, `human_review` and `precedent`, each with its search outcome, paths, latency and query names), `paths` (with nodes, ops, sessions, agents and a status of `violating`, `cleared`, `limited` or `info`), `sources`, `sink` (declared versus classified, with the reason), `approval` (whether one is available and what it would record), `latency_ms` per query and in total, `policy`, `evaluated_at`, `search_complete`, `indeterminate_checks`, `certificate` or `certificate_unavailable`, `contamination`, and `deterministic: true`.

Every check through the HTTP API, the agent runtime or the MCP `check_action` tool is appended to the graph as `(:Decision)-[:EVALUATES]->(:Action)`, readable at `GET …/guard/actions/{id}/decisions`. Read-only views (the console's decision page and metrics, `explain_decision`, `why_allowed`, re-adjudication and policy simulation) re-run the Guard without recording.

## Performance

On the demo graph a decision takes roughly 5–50 ms on embedded FalkorDB, and each decision carries its own per-query latency breakdown (visible in the console). How it scales with graph size, including a case that exceeded a pre-registered 1 s target, is on the [Benchmarks](/docs/benchmarks) page.
