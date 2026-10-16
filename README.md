# Custody

**A malicious instruction entered through one agent days ago, persisted in shared memory,
influenced another agent, and Custody reconstructed the full chain and stopped the
dangerous action.**

Custody gives a team of AI agents a shared memory in which every piece of information keeps
its provenance, stored as a graph in **FalkorDB**. Before any agent does something
outbound or irreversible, a **deterministic Guard** searches that graph completely (a
breadth-first search, read-only Cypher queries level by level) and decides ALLOW, REQUIRE
HUMAN APPROVAL or BLOCK, with the provenance path that caused the decision. When something
goes wrong, the **Warden** agent investigates and contains it through **MCP tools** that
run graph queries and graph algorithms; its own actions pass the same Guard.

> **Simulation, on purpose.** Acme Robotics is a synthetic company. In the demos the web
> pages, vault, Slack, email, the GitHub-hosted registry and the attacker's upload server
> are simulated in-process: no network request is made and nothing is delivered anywhere.
> "Day 1" and "Day 4" are simulated sessions on a simulated clock, and the agents follow
> scripted flows (no LLM is called; the scripted outputs are what a prompt-injected model
> would emit). A record/replay path for a real model run exists, but no real recording
> ships. What is real: the provenance recording, the FalkorDB graph and every Guard
> decision. Simulating the world is what makes the experiment safe to run and exactly
> reproducible.

![Attack demo: the blocked action and the provenance path that explains it](docs/screenshots/demo.png)

**Documentation:** the full docs (quickstart, installation, architecture, provenance graph,
Guard, Warden, MCP, integrating your own agents, console, demos, HTTP API, configuration,
CLI, benchmarks, deployment, security model, troubleshooting) are served by the app at
`/docs` (e.g. <http://localhost:5173/docs> in development). Their source is in
[frontend/src/docs/content/](frontend/src/docs/content/). Reference notes in this
repository: [Guard](docs/guard.md) · [graph model](docs/graph-model.md) ·
[Warden and MCP](docs/warden.md) · [benchmarks](bench/README.md).

---

## Contents

- [The problem](#the-problem)
- [The attack, step by step](#the-attack-step-by-step)
- [Why a provenance graph](#why-a-provenance-graph)
- [What "no path found" means](#what-no-path-found-means)
- [Guard](#guard-deterministic-graph-backed-decisions)
- [Warden and MCP tools](#warden-incident-response-through-mcp-tools)
- [Benchmarks](#benchmarks)
- [Architecture](#architecture)
- [Graph schema](#graph-schema)
- [How Custody uses FalkorDB](#how-custody-uses-falkordb)
- [Threat model and limitations](#threat-model-and-limitations)
- [The console](#the-console)
- [Local setup](#local-setup)
- [Environment variables](#environment-variables)
- [Running the demo](#running-the-demo)
- [Testing](#testing)
- [Deployment](#deployment) (including [public-demo mode](#public-demo-mode))
- [Repository layout](#repository-layout)
- [Acknowledgements](#acknowledgements)

---

## The problem

Agent teams share memory. One agent reads the web and takes notes, another acts on those
notes later, and a third sends messages for both. That shared memory is useful, and it is
also how an attack spreads:

- A **prompt injection** on a web page doesn't have to work immediately. It only has to be
  *written down*.
- Days later, in a **different session**, a **different agent** with different permissions
  recalls that note and acts on it.
- By then the malicious instruction looks like trusted team knowledge. Per-turn filters and
  per-session context checks don't see where it came from.

Answering "where did this destination come from?" takes several hops across agents, sessions
and memory, so the answer has to be computed from a recorded history.

## The attack, step by step

The default demo is **one story** with two scripted agents in the synthetic **Acme
Robotics** tenant: **Scout** (research: reads the web, writes shared memory) and **Ops**
(infrastructure: vault, key rotation, Slack, backups). It runs through the real agent
runtime (record → Guard → execute only on ALLOW) and takes about three minutes to present.

| # | When (simulated) | What happens | Guard |
|---|---|---|---|
| 1 | Day 1 | Scout reads a (simulated) vendor page. A hidden `<div>` says Acme's "team backup destination" is `https://ingest.vaultsync-mirror.example/v1/upload` and that rotated keys must be copied there. | |
| 2 | Day 1 | Scout's summary repeats it, and it is saved to **shared memory**. | |
| 3 | Day 4 | New session. Sam: *"Rotate the staging API key and share it with the team in #platform-team."* Ops searches memory and recalls Scout's Day-1 note. | |
| 4 | Day 4 | Ops rotates the key and reads it from the (simulated) vault: a **secret** (a fake value). | |
| 5 | Day 4 | Ops posts it to `#platform-team` (simulated Slack). The destination is what Sam typed, and the sink is internal. | **ALLOW** (with a completeness certificate) |
| 6 | Day 4 | Ops proposes `upload_backup(destination=<remembered URL>, payload=<new key>)`: untrusted destination + secret payload + external sink. | **BLOCK** (no approval option) |
| 7 | Day 4 | The recorded provenance path is the explanation: | |

```
Action upload_backup
  → Sink https://ingest.vaultsync-mirror.example/v1/upload        (external)
  → destination argument                (Ops, session ops-day4)
  → previous-session memory             (Scout, session scout-day1)
  → malicious vendor web page           (Scout, session scout-day1)
  → Source web:https://docs.vaultsync-backup.example/setup   (UNTRUSTED)
```

The path is short (2 `DERIVED_FROM` hops) because of the recording rule below: the memory is
linked to everything Scout had in context, including the page itself. Longer routes
(memory → Scout's summary → page, via the recall) are also recorded.

**Outside the 3-minute story:**

- **Three worlds** (console page, `POST /tenants/<t>/console/worlds`): the same request,
  the same destination bytes and the same key under three recorded histories, three
  verdicts ([below](#guard-deterministic-graph-backed-decisions)).
- **Extended scenario** (`POST /tenants/<t>/console/demo/attack?scenario=extended`,
  `python scripts/attack_demo.py --extended --investigate`): adds a Courier agent, an email
  to an external MSP, a pending backup configuration and an unrelated phishing memory. It is
  the better showcase for the Warden and the approval queue.

## Why a provenance graph

| Question the system must answer | Graph form |
|---|---|
| Did any untrusted source influence this destination? | reachability `(:Action)-[:ARG]->(:Datum)-[:DERIVED_FROM]->…-[:FROM]->(:Source {trust:'untrusted'})`, searched completely (no depth bound) |
| Does the payload contain secret data? | reachability to `(:Datum {sensitivity:'secret'})` |
| Across which sessions and agents? | the nodes on that path |
| What else did this page touch? | forward traversal from the Source |
| Which memory matters most? | betweenness centrality over the provenance subgraph |
| Which contamination belongs together? | weakly connected components |

Every agent turn, memory, **recall** and **message** is a `Datum`, so one traversal crosses
LLM calls, sessions, agents and time without special cases. Trust is not copied onto data:
it lives on Sources and is evaluated per path at decision time. **Trust labels are policy
inputs** that whoever registers a Source (or tenant policy) assigns, and a human can later
revoke; Custody does not infer them.

The Guard needs no LLM to judge whether a destination is suspicious: graph reachability
answers that, and the path is the evidence.

## What "no path found" means

Every negative result depends on one assumption: **the graph does not silently omit a
context dependency.** The default rule, enforced by the agent runtime
(`custody/runtime/runtime.py`):

> Every LLM output, tool-call argument, memory and message gets a `DERIVED_FROM` edge to
> **everything in the session's context window**. `derived_from=` can add parents but never
> narrow the context. Everything shown to the model enters the context: user input,
> fetched pages, vault reads, recalls, memory-search results, received messages, typed
> values.

This **deliberately over-approximates** influence. The graph may report influence that did
not happen (a false alarm), but it does not drop a dependency the runtime saw. So the
strongest negative statement Custody makes is:

> *Relative to the recorded provenance graph, current trust labels, and a complete
> traversal, no untrusted influence path was found.*

It is never a claim that the action is safe. Concretely:

- **Complete traversal.** "No path" is reported only when the search exhausted the graph
  (`NO_PATH`). A node/time limit or a query error gives `INDETERMINATE`, which the Guard
  treats as a violation (fail closed) and never as ALLOW.
- **Certificate.** An ALLOW from the provenance checks carries a *Provenance Completeness
  Certificate* stating exactly that claim, the graph version, every reached root Source with
  its trust label, and whether every model output in the ancestry recorded its full context
  (`STRONG`) or not (`DOWNGRADED`). Details: [docs/guard.md](docs/guard.md#provenance-completeness-certificate).
- **Over-approximation costs false positives.** A value the user gave in other words is
  attributed to the whole context, and an output produced while a secret was in context is
  labelled secret. Label creep for tool arguments is limited by one recorded exception,
  *exact-value attribution* ([docs/guard.md](docs/guard.md#label-creep-mitigation)).
- **Unrecorded influence is invisible.** An integrator calling the Recorder or the HTTP API
  directly must pass the complete context as `derived_from` (or declare
  `coverage="REDUCED"`, which downgrades the certificate). Implicit flows, where untrusted
  text makes a model *choose* between trusted values, are not data flow and are out of scope.

Tests: `tests/unit/test_context_soundness.py`, `tests/guard/test_trace_completeness.py`,
`tests/guard/test_certificate.py`, `tests/guard/test_certificate_coverage.py`.

## Guard: deterministic, graph-backed decisions

| Check | Fires when |
|---|---|
| **Integrity** | a destination argument has an uncleared path to an untrusted Source (cleared = through human-endorsed data, or a typed value whose `max_risk` covers the action), or the sink's literal destination isn't bound to any recorded destination Datum |
| **Confidentiality** | a payload argument derives from a `secret` Datum **and** the sink is external |
| **Lethal trifecta** | integrity **and** secret payload **and** external sink |
| **Human review** | the action type always needs a human: Warden disclosures and security-loosening remediations |
| **Precedent** | a human already rejected a secret-bearing action to the same Sink |

| Result | Verdict | Approval |
|---|---|---|
| nothing fires | `ALLOW` | – |
| integrity, confidentiality or human review | `REQUIRE_HUMAN_APPROVAL` | yes: endorse the data, or approve these checks for this action only |
| a search was INDETERMINATE (no trifecta) | `REQUIRE_HUMAN_APPROVAL` | **no**: nothing concrete to approve; a later complete re-check decides |
| lethal trifecta, or one that cannot be ruled out | **`BLOCK`** | **never**: the API returns 403 and the UI shows no button |
| precedent escalation | **`BLOCK`** | never |

(The MCP `check_action` result abbreviates the middle verdict to `REQUIRE_APPROVAL`.)

**How the verdict is computed.** Integrity and confidentiality come from a **complete**
breadth-first search over `DERIVED_FROM` (visited set, cycle-safe, no depth bound;
`custody/graph/traversal.py`), one read-only query per level. Each search ends `PATH_FOUND`
(with a witness path), `NO_PATH` (graph exhausted) or `INDETERMINATE` (limit or error); only
`NO_PATH` passes. A depth-bounded path query (`*0..25`, 250 ms timeout) runs first for
evidence: a violating path it returns is real and confirms the violation, but "nothing
within 25 hops" is never taken as clean, and the complete search decides.

**Any route decides; the shortest route only explains.** A one-hop route to something Sam
typed does not hide a 60-hop route to a vendor page next to it, and path length never enters
the verdict (`tests/guard/test_any_route.py`). On a violation, the Guard also lists every
distinct untrusted root and whether the routes are `independent`, `converging` (e.g. through
the shared memory), `direct` or `unverified` (`custody/guard/contamination.py`; explanation
only).

**Deterministic and monotone in agent activity.** The decision is a pure function of graph
facts, the static policy and the trust labels; the Metrics page re-runs a check live and
confirms identical output. Agent activity only appends provenance, which can add paths but
never remove one. What can make a later re-check more permissive is a human act recorded in
the graph (an endorsement, an action-scoped approval, restoring a Source's trust) or a policy
change; a trust revocation or a human rejection makes it stricter.

**Same bytes, different provenance (Three worlds page).** One Day-4 request, the same
destination bytes and the same key, three recorded histories: **A** the URL is a trusted
registry entry a security lead pre-approved for secret egress → ALLOW with a certificate;
**B** Priya typed it (trusted, but nobody approved secrets to it) → REQUIRE_HUMAN_APPROVAL;
**C** it came from the poisoned memory → BLOCK. *The content can be identical. The
provenance changes the decision.* (`custody/demo/worlds.py`.)

![Three worlds: same request, same bytes, three verdicts](docs/screenshots/worlds.png)

**Other graph-backed policy features** (deterministic, citing exact graph facts):

- **Secret-egress endorsement** (`POST …/guard/endorse {"egress": true}`): a human vouches
  that secrets may go to the destination value a Datum holds. It clears confidentiality only
  if integrity is clean, the destination is bound, and a Guard-followed ancestor of the
  destination holds exactly the sink's destination value (World A). Known edge case: the
  code does not check that the confidentiality search itself completed; if it was
  INDETERMINATE, the Guard's final fail-closed assertion turns the check into an error
  (HTTP 500) rather than an ALLOW.
- **Precedent escalation**: a would-be REQUIRE_HUMAN_APPROVAL with a secret payload becomes
  BLOCK when `(:Approval {verdict:'rejected'})-[:REJECTS]->(prev)-[:TO]->(:Sink)<-[:TO]-(current)`
  exists, cited verbatim. No similarity, no embeddings.
- **Retroactive re-adjudication** (`POST …/guard/sources/<id>/revoke`, or the Warden's
  `revoke_source_trust`): a previously trusted Source is marked untrusted; Custody walks
  forward completely, re-runs the current Guard on every downstream action and reports
  *original → current* (e.g. `ALLOW → BLOCK`, `ALLOW → REQUIRE_HUMAN_APPROVAL`,
  `UNCHANGED`). Original Decisions and executions are untouched; each re-check is stored as
  a `(:Readjudication)`.
- **Chokepoints** (Warden `find_chokepoints`, and in the decision view of a non-ALLOW
  action): which single node, if removed, breaks every recorded untrusted path? Each
  candidate is verified by re-running the complete search without it. A per-node what-if
  over today's graph, not a min-cut.

Full reference (approval scopes, certificate fields, sinks, policy, HTTP):
[docs/guard.md](docs/guard.md).

## Warden: incident response through MCP tools

The Warden is an agent whose only capabilities are 17 MCP tools. A planner chooses them:
**Claude** with tool use when `ANTHROPIC_API_KEY` is set, otherwise a deterministic offline
**playbook** that speaks the same protocol. Its role is narrow: **trace → re-adjudicate →
contain → explain**. The deterministic Guard remains the authority for every verdict,
including on the Warden's own actions.

| Tool | What it does on the graph |
|---|---|
| `begin_investigation` | records the operator's request as trusted user input; every Warden action derives from it |
| `find_sources` | locate the reported source; untrusted sources with the most downstream influence first |
| `trace_back` | action → paths to its sources |
| `trace_forward` | source → every derived datum, memory, recall, message and action, separating direct from context-only influence |
| `find_chokepoints` | single nodes whose removal breaks every recorded untrusted path to an action (verified by re-search) |
| `rank_risky_memories` | taint × reach, plus **`algo.betweenness`** centrality |
| `cluster_incidents` | **`algo.WCC`** over the contamination subgraph, on a **`GRAPH.COPY`** sandbox |
| `simulate_policy` | re-runs the Guard under another policy on a `GRAPH.COPY` clone; the live graph is never written |
| `check_action` | the Guard as a service: verdict, fail-closed flag, triggered checks, evidence paths, certificate summary on ALLOW; writes a Decision audit node |
| `explain_decision` | the recorded Decision next to the same Guard re-run on today's graph; read-only |
| `why_allowed` | an ALLOW's certificate rendered as fixed-template text (traversal, root Sources and labels, coverage, graph version); no model-written explanation |
| `quarantine` | a **Guard-checked** `quarantine_memory` action; quarantined memories are hidden from normal retrieval and recall |
| `revoke_source_trust` | **tightening**: a Guard-checked action that marks a Source untrusted and re-adjudicates history |
| `propose_loosening` | **loosening** (unquarantine, endorse, restore trust, weaken a restriction): recorded and Guard-checked, always waits for a human |
| `draft_disclosure` / `propose_disclosure` | drafts for external recipients of contaminated data; every factual sentence must cite graph ids in the traced incident (others are removed); proposing returns REQUIRE_HUMAN_APPROVAL |
| `send_approved_disclosure` | sends (simulated) only after a human approval **and** a fresh Guard ALLOW |

- **Asymmetric remediation.** Tightening runs on a Guard ALLOW. Loosening is only ever
  proposed; a human approves it through the Guard API (or `Warden.approve_remediation`) and
  an operator executes it from Python (`Warden.execute_approved_remediation`, not exposed
  over MCP).
- **Quarantine prevents future recall without deleting history.** Recorded provenance,
  Decisions and earlier recalls stay; the Day-4 action re-checked after quarantine keeps its
  BLOCK and its path. Forensic reads can still see quarantined memories.
- **No approval tool over MCP.** The Warden cannot approve its own work. Tool results that
  contain attacker-written text are marked as data, never instructions.
- **Citations are grounding, not truth.** The check guarantees a disclosure sentence cites
  existing, in-scope graph ids; a false sentence citing in-scope ids would pass, which is why
  a human approves every disclosure.

**Any MCP-speaking agent can use the Guard** (`check_action`, `explain_decision`) on actions
it recorded through the Recorder API. Custody does not enforce anything over MCP: the caller
must execute only on ALLOW, and the verdict is only as good as the provenance the caller
recorded. (The in-process runtime does enforce: `AgentSession.call_tool` executes only on
ALLOW.)

Details and Claude Desktop / Claude Code setup: [docs/warden.md](docs/warden.md) and the
docs site's *Warden* and *MCP* pages.

## Benchmarks

> **What the benchmark can and cannot show.** The synthetic generator writes the
> ground-truth causal history and Custody records that same history, so Custody's accuracy
> on in-scope cases is close to guaranteed by construction. This is **not** evidence that
> "graphs infer attacks better than RAG". It measures: *if provenance is recorded, how much
> does explicit provenance help compared with reconstructing influence from content, and
> how suitable is FalkorDB for querying it?* A recursive SQL CTE over the same edges matches
> FalkorDB on correctness (330/330).

Hypotheses and falsification conditions were written before the run
([bench/HYPOTHESES.md](bench/HYPOTHESES.md)); every number below is from the committed run
([bench/results/REPORT.md](bench/results/REPORT.md)). How to run them:
[bench/README.md](bench/README.md).

![Share of cases handled correctly, by method and category](bench/results/figures/heatmap.png)

**In-scope set** (290 of 330 cases; excludes implicit flow and over-approximation, which
are outside Custody's model, and the two endorsement categories, whose truth is defined by
recorded policy):

| method | precision | recall | F1 | negatives that are completed traversals |
|---|---|---|---|---|
| Custody (FalkorDB) / recursive SQL CTE | 1.00 | 1.00 | 1.00 | 100 / 100 |
| Cypher `*0..25` (bounded) | 0.97 | 0.96 | 0.97 | 0 |
| TF-IDF RAG, best of 304 operating points (hindsight) | 0.89 | 0.82 | 0.85 | 0 |
| Multi-hop RAG | 0.88 | 0.75 | 0.81 | 0 |
| String match + context attribution | 1.00 | 0.63 | 0.77 | 0 |
| String exact | 0.86 | 0.63 | 0.73 | 0 |
| Keyword (injection-phrase) scan | 0.75 | 0.16 | 0.26 | 0 |

- **Where recorded provenance helps most.** Decoys carrying *the same bytes* as an untrusted
  page but coming from a trusted source are escalated 100% of the time by string exact/host
  matching and every retrieval method, 0% by Custody. Split-source attacks defeat string
  matching and pre-set single-hop TF-IDF retrieval; deep chains (10–40 hops) defeat
  retrieval (0–20%), and the bounded Cypher query missed all 8 chains of 26–40 hops. Only the graph methods' "nothing found" answers are
  completed traversals (NPV 100%, vs ≤70% for content methods and 92% for `*0..25`).
- **Where content methods are as good.** Direct, cross-session, high fan-in and
  transformed-secret attacks (string, TF-IDF and multi-hop retrieval at 100%); TF-IDF retrieval at its
  hindsight-best point finds 95% of paraphrase-laundered destinations; a context-aware
  string rule has zero false escalations on the in-scope decoys.
- **Custody's own errors.** Implicit flows (10/10 missed, out of scope) and
  over-approximation (10/10 false alarms; 3/3 agent summaries flagged as secret because the
  key was in context).
- **FalkorDB vs SQL.** Same answers. SQLite's in-process CTE is much faster per decision
  (median 0.27 ms vs 22 ms for the full Guard, which also does more work). Path extraction
  depends on approach more than engine: enumerating paths explodes on dense sessions in
  *both* (FalkorDB `*1..N`: 1.3 s at 18 turns, timeout at 22; SQLite path-string CTE: 8.3 s
  at 22), while level-by-level search stays at 3.0–4.5 ms (FalkorDB) and 0.7–1.4 ms (SQLite).
- **Falsification condition F3 triggered.** A clean ALLOW at 10k ancestors takes 1.3 s
  (above the pre-registered 1 s). A 100k fan-in fails closed (INDETERMINATE) under the
  shipped 2 s limit.
- **Not measured.** The LLM judge (no API key; the harness is ready) and neural embeddings
  (model download blocked).

![Negative-claim validity](bench/results/figures/negative_claims.png)

## Architecture

```
          ┌────────────────────────── React console (Vite, TS) ───────────────────────────┐
          │ Dashboard · Attack demo · Three worlds · Provenance graph · Guard decisions   │
          │ Approvals · Warden (incl. re-adjudications) · Metrics                         │
          └─────────────────────────────────────┬─────────────────────────────────────────┘
                                                │ /api (same origin)
┌───────────────────────────────────────────────┴───────────────────────────────────────────┐
│ FastAPI (every route is tenant-scoped: /tenants/{t}/…)                                     │
│  record/* · sources · data/* · actions/*   Recorder: the write path for provenance          │
│  guard/*      check · approve · reject · endorse · sources/{id}/revoke · readjudications    │
│  console/*    read models for the UI · demo / worlds / Warden runners                       │
└──────┬──────────────────────────┬─────────────────────────────────┬────────────────────────┘
       │                          │                                 │ in-process MCP client
┌──────┴───────┐   ┌──────────────┴───────────┐        ┌───────────┴──────────────────────────┐
│ Agent runtime│   │ Guard (deterministic)    │        │ Warden MCP server (17 tools)          │
│ scout / ops /│──▶│ complete BFS per check + │◀───────│ trace · chokepoints · rank (between-  │
│ courier      │   │ static tenant policy +   │        │ ness) · cluster (WCC) · quarantine · │
│ shared memory│   │ trust labels             │        │ revoke · disclose · check_action      │
└──────┬───────┘   └──────────────┬───────────┘        │ planner: Claude (tool use) or playbook│
       │                          │                    └───────────┬──────────────────────────┘
       └──────────────────────────┴────────────────┬───────────────┘
                                        ┌──────────┴───────────┐
                                        │ FalkorDB             │  graph per tenant: custody:<tenant>
                                        │ (local · Cloud ·     │  GRAPH.COPY sandboxes for what-ifs
                                        │  embedded)           │
                                        └──────────────────────┘
```

The same MCP server also runs standalone (stdio, Streamable HTTP or SSE) for Claude
Desktop, Claude Code or the MCP Inspector. See [docs/warden.md](docs/warden.md#running).

## Graph schema

| Node | Key properties |
|---|---|
| `Source` | `kind` (user, web, vault, email, …), **`trust`** (trusted / untrusted), `trust_original`, revocation fields |
| `Datum` | `kind`, `preview` (secrets masked), `fingerprint`, **`sensitivity`**, `agent`, `session_id`, `endorsed`, `coverage` |
| `Datum:Memory` | + `in_quarantine`, `metadata.key` |
| `Datum:Recall` | one retrieval of a memory into a session |
| `Datum:Message` | inter-agent message, `metadata.sender` / `recipient` |
| `Datum:Typed` | a validated value extracted from untrusted content by the quarantined reader, with the highest risk tier it may influence (`max_risk`) |
| `Action` | `action_type`, `agent`, `status` |
| `Sink` | `destination`, `kind` (externality decided by policy, not the agent) |
| `Approval` | `approver`, `verdict` (approved / rejected), `reason`, `egress` |
| `Decision` | Guard audit record: verdict, triggered checks, latency |
| `Quarantine` / `QuarantineLift` | Warden containment, and a human-approved lift |
| `TrustRevocation` / `TrustRestoration` / `Readjudication` | trust changes and the re-checks they caused |
| `GraphMeta` / `Run` | version counters for certificates; demo and Warden run records |

| Relationship | Meaning |
|---|---|
| `(:Datum)-[:FROM]->(:Source)` | where it entered |
| `(:Datum)-[:DERIVED_FROM {op, attribution}]->(:Datum)` | `op`: derive, save, recall, send, attribute, extract, …; `attribution: "context"` marks edges the Guard does not follow |
| `(:Action)-[:ARG {role}]->(:Datum)` | `role`: destination, payload, … |
| `(:Action)-[:TO]->(:Sink)` | where it sends |
| `(:Approval)-[:ENDORSES {egress}]->(:Datum)` | a human vouches for data (optionally for secret egress) |
| `(:Approval)-[:APPROVES {checks}]->(:Action)` / `-[:REJECTS]->` | action-scoped human decision |
| `(:Decision)-[:EVALUATES]->(:Action)` | audit trail |
| `(:Quarantine)-[:QUARANTINES]->(:Memory)`, `-[:VIA]->(:Action)` | containment, and the Guard-checked action that did it |
| `REVOKES`, `RESTORES`, `READJUDICATES`, `PRODUCED`, `LIFTS` | trust changes, re-checks and quarantine lifts |

Provenance (Datums, `DERIVED_FROM`, `FROM`, `ARG`, `TO`) is append-only; a few flags are
updated in place with an audit node next to them (`Action.status`, `Datum.endorsed`,
`Memory.in_quarantine`, `Source.trust`). Full reference: [docs/graph-model.md](docs/graph-model.md).

## How Custody uses FalkorDB

- **One graph per tenant** (`custody:<tenant>`), so tenants are isolated and can be dropped
  atomically. The three-worlds comparison uses its own graph (`<tenant>-worlds`).
- **Complete level-by-level traversals** for every Guard verdict, the certificate's ancestor
  walk, forward re-adjudication and chokepoint verification. Lineage, path-to, trace views,
  exact-value attribution candidates and Warden analyses are bounded by
  `CUSTODY_MAX_TRACE_DEPTH` (25); variable-length `*0..25` patterns supply evidence paths.
  Range indexes on ids, kinds, sessions and fingerprints.
- **Read-only queries** (`GRAPH.RO_QUERY`) for every check, so a decision can't write.
- **Graph algorithms**: `algo.betweenness` (risky memories) and `algo.WCC` (incident
  grouping).
- **`GRAPH.COPY` sandboxes** for incident clustering and policy simulation. The clone is
  deleted afterwards. If a managed service disallows `GRAPH.COPY`, Custody falls back to
  read-only queries on the live graph and union-find clustering, and the result says so.
- **Three deployment modes, one code path**: local server (Docker), **FalkorDB Cloud**
  (host/port/username/password, optional TLS, or a `redis://` / `rediss://` URL), and
  embedded `falkordblite` for tests and laptops.

## Threat model and limitations

**In scope.** Explicit data flow that the runtime records: user messages, web pages,
emails, vault reads, LLM outputs, memories, recalls and inter-agent messages, across any
number of sessions and agents. The attacker controls the content of untrusted sources and
can make a model write anything into memory or tool arguments. Sinks are classified by
tenant policy and fail closed (unknown kinds and look-alike domains are external).

**Assumptions.** The runtime (or integrator) records context faithfully; Source trust labels
are correct inputs; approvers are humans authenticated outside Custody.

**Limitations.**

- **Conclusions apply to the recorded graph only.** Influence that never passed through the
  Recorder is invisible, and a caller over MCP that records less than the full context can
  get an ALLOW it should not.
- **Implicit flows are out of scope**: untrusted content convincing a model to *choose*
  between two trusted values (`#security` over `#general`) leaves no data-flow path. Timing
  and other side channels too.
- **Over-approximation** produces false alarms by design (see
  [What "no path found" means](#what-no-path-found-means)).
- **Resource limits fail closed**: very large ancestries (≈100k Datums) return
  INDETERMINATE under the shipped 2 s limit, which is a REQUIRE_HUMAN_APPROVAL without an
  approval option, or a BLOCK if the trifecta can't be ruled out.
- **The demo is synthetic** and scripted; no real LLM recording ships, and the LLM-judge
  baseline was not run.
- **No authentication.** The console and API have none; the Recorder's `/record/approval`
  and `PATCH …/actions/{id}/status` endpoints write approvals and statuses without the
  Guard's approval guardrails and are meant for a trusted integrator only. Public-demo mode
  blocks them.

## The console

| Page | Shows |
|---|---|
| **Dashboard** | agents (with contamination flags), allowed / approval / blocked counts, recent actions, active incidents, quarantined and tainted memories |
| **Attack demo** | one-click run and reset, the 7-step story (with what is simulated in each step), the graph growing step by step, the certificate on the ALLOW, the trifecta, the BLOCK and the final path |
| **Three worlds** | the same request and bytes under three histories, with the three verdicts side by side |
| **Provenance graph** | **Nodes** / **Agents** toggle. *Agents* collapses the graph to who influenced whom (`web:vendor page → Scout → Memory m → Ops`, `GET …/console/influence`); clicking a channel reveals the underlying path. *Nodes*: every Source, Datum, Memory, Recall, Message, Action, Sink and Approval; trusted, untrusted, secret, quarantined and blocked are distinguishable by colour *and* shape. |
| **Guard decisions** | per action: verdict, checks, trifecta checklist, sink classification, the shortest uncleared route (labelled as evidence), certificate on ALLOW, chokepoints on non-ALLOW, latency breakdown and the audit trail stored in the graph |
| **Approvals** | the risky path, why approval is needed, approve/reject with a reason (written to the graph). After an approval a **decision flip** card shows `REQUIRE_HUMAN_APPROVAL → Human ENDORSES/APPROVES → ALLOW` read back from the graph. Lethal-trifecta blocks have no buttons (and the API refuses them). Approved disclosures can then be sent. |
| **Warden** | free-text commands, planner choice, every MCP tool call with a readable rendering and the raw JSON, and the re-adjudication reports |
| **Metrics** | Guard latency (median of live re-runs) and breakdown, path length, sessions and agents crossed, affected memories / agents / actions, determinism check, the Cypher patterns used |

| | |
|---|---|
| ![Dashboard](docs/screenshots/dashboard.png) | ![Guard decision](docs/screenshots/guard.png) |
| ![Provenance graph](docs/screenshots/graph.png) | ![Approvals](docs/screenshots/approvals.png) |
| ![Warden](docs/screenshots/warden.png) | ![Metrics](docs/screenshots/metrics.png) |

## Local setup

Requirements: Python 3.10+ (3.12+ for embedded FalkorDB), Node 20.19+ or 22.12+, and either Docker or
`falkordblite`. The shortest path is the *Quickstart* page of the docs site (`/docs/quickstart`).

```bash
# backend
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev,warden]"

# frontend
cd frontend && npm ci && cd ..
```

Then pick a database:

```bash
docker compose up -d falkordb                      # A: local FalkorDB on :6379 (browser UI on :3000)
export CUSTODY_FALKORDB_EMBEDDED_PATH=.data/custody.db   # B: embedded, no Docker (Python 3.12+)
cp .env.example .env                               # C: FalkorDB Cloud: fill in host/port/user/password
```

Run it (two terminals):

```bash
uvicorn custody.api.app:app --reload --port 8000   # API: http://localhost:8000/swagger
cd frontend && npm run dev                         # UI:  http://localhost:5173 (proxies /api)
```

Or as one process serving the built UI:

```bash
cd frontend && npm run build && cd ..
CUSTODY_STATIC_DIR=frontend/dist uvicorn custody.api.app:app --port 8000   # http://localhost:8000
```

The built UI includes the documentation site at `/docs`; FastAPI's interactive API reference
is at `/swagger` (and `/redoc`, `/openapi.json`). When the API serves the UI, API routes are
also reachable under `/api` (e.g. `/api/health`).

`make install`, `make api-embedded`, `make ui`, `make test` wrap the same commands.

## Environment variables

| Variable | Default | Purpose |
|---|---|---|
| `CUSTODY_FALKORDB_HOST` / `_PORT` | `localhost` / `6379` | FalkorDB server or Cloud instance |
| `CUSTODY_FALKORDB_USERNAME` / `_PASSWORD` | – | FalkorDB Cloud credentials |
| `CUSTODY_FALKORDB_SSL` | `false` | TLS to the server |
| `CUSTODY_FALKORDB_URL` | – | `redis://user:pass@host:port` or `rediss://…`; overrides host/port |
| `CUSTODY_FALKORDB_EMBEDDED_PATH` | – | run an embedded FalkorDB (`falkordblite`) |
| `CUSTODY_GRAPH_PREFIX` | `custody` | graph names are `<prefix>:<tenant>` |
| `CUSTODY_MAX_TRACE_DEPTH` | `25` | depth bound for lineage, path-to and trace views, exact-value attribution candidates and Warden analyses. Guard verdicts use a complete search; Guard evidence queries use `GuardPolicy.max_depth` |
| `CUSTODY_STATIC_DIR` | – | serve the built UI at `/` |
| `CUSTODY_PUBLIC_DEMO` | `false` | public-demo mode (see [Deployment](#public-demo-mode)) |
| `CUSTODY_DEMO_TENANT` | `acme` | the only tenant reachable in public-demo mode |
| `CUSTODY_DEMO_RESET_MIN_INTERVAL_S` | `10` | rate limit for Reset Demo |
| `CUSTODY_CORS_ORIGINS` | – | comma-separated origins, only when the UI is hosted elsewhere |
| `ANTHROPIC_API_KEY` | – | lets the Warden plan with Claude; without it, the offline playbook |
| `CUSTODY_WARDEN_MODEL` | `claude-sonnet-5-5` | model for the Claude planner |
| `CUSTODY_DEMO_MODE` | `auto` | primary demo: `auto` replays a recorded **real-model** run that contains a BLOCK, else scripted; `recorded` also accepts a test-double recording (labelled as such); `scripted` |
| `CUSTODY_DEMO_LLM_MODEL` | Warden default | model used by `scripts/record_llm_run.py` |
| `VITE_API_BASE` | `/api` | (frontend build) API base URL |
| `VITE_TENANT` | `acme` | (frontend build) tenant shown in the console |
| `CUSTODY_API_URL` | `http://127.0.0.1:8000` | (frontend dev server) proxy target for `/api` |

`.env` is read only for the `CUSTODY_*` settings in `custody/config.py` (database, graph,
HTTP, public demo). `ANTHROPIC_API_KEY`, `CUSTODY_WARDEN_MODEL`, `CUSTODY_DEMO_MODE` and
`CUSTODY_DEMO_LLM_MODEL` are read from the process environment only, so export them.
Benchmark-only variables are listed in [bench/README.md](bench/README.md). See
[.env.example](.env.example).

## Running the demo

1. Open the console and click **▶ Run attack scenario**. The tenant graph is wiped and the
   simulated Day 1 and Day 4 sessions are recorded. The banner and the "What is simulated"
   panel say what is synthetic.
2. Watch the 7 steps play, or step through them: Slack post **ALLOW** with its certificate
   (step 5), upload to the attacker **BLOCK** (step 6), the path back to the vendor page
   (step 7).
3. Click **Open decision →** for the Guard view: the violated checks, the trifecta, no
   approval option, the complete-search outcome, chokepoints and latency.
4. Optional 30-second coda: the **Three worlds** page (same bytes, three verdicts).
5. Optional, after the story: the **Provenance graph** and **Metrics** pages; the Warden and
   the approval queue on the extended scenario (load it with
   `curl -X POST localhost:8000/tenants/acme/console/demo/attack?scenario=extended`; the
   console has no button for it).

The same story from a terminal:

```bash
python scripts/attack_demo.py --embedded .data/cli.db
python scripts/attack_demo.py --embedded .data/cli.db --extended --investigate   # extended + Warden
```

### Recorded LLM execution, deterministic replay

By default the agents follow a script. To show a model's own behaviour with the
reliability of a scripted demo, record **one** real run and replay it:

```bash
ANTHROPIC_API_KEY=… python scripts/record_llm_run.py   # writes custody/demo/fixtures/llm_run.json
```

Scout and Ops are driven by the model (tool use) through the normal runtime: each model text
is linked to the whole context window, every tool result it sees enters the context, and
`post_slack` / `upload_backup` go through the Guard. The fixture stores each request's hash,
the model's response and the tool results; it contains only the synthetic scenario and never
the API key (checked on write).

**Run attack scenario** then replays it with **no model call**: every request and tool
result must match the recording byte for byte (otherwise `ReplayDivergence` and the scripted
story is used), deterministic ids rebuild the same graph, and the Guard recomputes the same
verdicts and paths. A real recording is labelled **"Recorded real LLM execution —
deterministic replay"**; a test-double recording (accepted only with
`CUSTODY_DEMO_MODE=recorded`) is labelled "Recorded test-double execution (not a real
model)". With no usable recording, or one in which the model never attempted the
exfiltration (no BLOCK), the demo is the scripted simulation.

**Status: no real recording ships in this repository** (the environment it was built in has
no API key). The record/replay path is tested with a deterministic stand-in model
(`tests/integration/test_llm_replay.py`).

## Testing

```bash
pytest                                   # 311 backend tests (embedded FalkorDB, or CUSTODY_TEST_FALKORDB_HOST=localhost)
ruff check custody tests scripts bench   # Python lint

cd frontend
npm test                                 # 41 unit/component tests (incl. the docs site) (Vitest + Testing Library)
npm run lint && npm run typecheck && npm run format:check
npm run build && npx playwright test     # end-to-end: real backend + built UI + Chromium
```

- **Backend** (`tests/`): model, graph writes, multi-hop provenance, every Guard check,
  approval path, certificate and completeness case, runtime enforcement, every Warden tool,
  remediation asymmetry and citations, the MCP server in-process and over stdio, LLM record
  → replay, and the console API end to end (including that a lethal-trifecta action can't be
  approved and that raw secrets never reach the UI), plus a smoke run of the benchmarks.
- **Frontend** (`frontend/src/**/*.test.tsx`): the provenance chain, decision view, approvals
  (no button for blocks), dashboard, Warden activity, three worlds and demo timeline.
  Fixtures are real API responses (`python scripts/export_ui_fixtures.py`).
- **End-to-end** (`frontend/e2e/demo.spec.ts`, 8 tests): the primary demo (ALLOW with
  certificate → BLOCK → path), the extended scenario (Warden → approvals → send), the graph
  inspector, the 403 on trifecta approval, three worlds with a chokepoint, the approval
  flip and agent-influence view, and no horizontal scroll at phone width.
  `docs.spec.ts` (2 tests) checks the documentation site as the API serves it: deep links,
  screenshots, search, the console ↔ docs links and phone width.
  `screenshots.spec.ts` (`SCREENSHOTS=1`) regenerates `docs/screenshots/` and
  `docs-screenshots.spec.ts` (`DOCS_SCREENSHOTS=1`) the docs site's images; both are skipped
  otherwise.
- **Docs site** (`frontend/src/docs/docs.test.tsx`): every navigation page has content,
  every image is used and exists, no broken internal links or anchors, and every `repo:`
  link points at a file that exists.

Playwright launches the API itself with an embedded FalkorDB. Set `PYTHON=` if your venv
lives elsewhere, and `PW_CHROMIUM=/path/to/chrome` to use a preinstalled browser instead of
`npx playwright install chromium`.

## Deployment

**Single container** (API and UI on one origin):

```bash
docker build -t custody .
docker run -p 8000:8000 \
  -e CUSTODY_FALKORDB_HOST=<cloud-host> -e CUSTODY_FALKORDB_PORT=<port> \
  -e CUSTODY_FALKORDB_USERNAME=<user> -e CUSTODY_FALKORDB_PASSWORD=<password> \
  custody
```

or locally with the database: `docker compose --profile app up --build`. The image listens
on `$PORT` (default 8000), so it runs as-is on Render, Railway, Fly.io or Cloud Run. Point it
at **FalkorDB Cloud** with the variables above and health-check `/api/health`.

The image also installs `falkordblite`, so it can run without a database server: set
`CUSTODY_FALKORDB_EMBEDDED_PATH` (e.g. `/tmp/custody.db`) instead of the `CUSTODY_FALKORDB_*`
connection variables. The embedded file lives in the container's filesystem and is lost on
restart or redeploy unless you mount a persistent disk; that is fine for public-demo mode,
which re-seeds the demo tenant at startup.

**Split hosting**: build the UI with `VITE_API_BASE=https://api.example.com/api` and host
`frontend/dist` on any static host (with an SPA fallback to `index.html`). Set
`CUSTODY_CORS_ORIGINS` on the API to the UI's origin.

The console has no authentication. Outside public-demo mode, put it behind your own auth
proxy before exposing it.

### Public-demo mode

`CUSTODY_PUBLIC_DEMO=true` lets you share a read-only deployment **without** building an auth
system (`custody/api/public_demo.py`, `make api-public`):

- **One synthetic tenant** (`CUSTODY_DEMO_TENANT`, default `acme`), seeded at startup with
  the primary demo and the three worlds. Every other tenant path answers 404.
- **Read-only.** Only GET/HEAD/OPTIONS, plus `POST …/console/demo/reset`. Recorder writes,
  Guard check/approve/reject/endorse/revoke, running scenarios, the Warden (which could call
  a paid LLM API) and sending disclosures all return 403. The UI hides or disables those
  controls and shows a "Public demo · read-only" tag.
- **Reset Demo** restores the initial state **deterministically**: counter-based ids and a
  fixed simulated clock, so the graph is identical after every reset (tested node by node).
  Rate-limited (one reset per 10 s by default; 429 otherwise).
- **No configuration exposed**: `/swagger`, `/redoc` and `/openapi.json` are off (the `/docs`
  documentation site stays available); `/health`
  returns status, FalkorDB reachability, version, the public-demo flag and the demo tenant.
- **No real credentials in the data**: the vault and its keys are simulated fakes, and raw
  secret values never reach the graph or any API response (tested).

Limitations: this is not authentication or abuse protection. There is no per-client rate
limiting beyond the reset limiter, GET endpoints still run real graph queries (bounded by
server-side timeouts), and anyone can reset the demo for everyone. Run it on its own
FalkorDB (or the embedded one), never on a database that holds real tenants, and don't set
`ANTHROPIC_API_KEY` or FalkorDB Cloud credentials you would mind losing control of on a
public host.

## Repository layout

```
custody/
  graph/        model, schema, repository (Cypher), traversal.py (complete, fail-closed search)
  recorder/     the provenance write path, exact-value attribution, typed-value risk
  runtime/      agent sessions + tool lifecycle (record → Guard → execute on ALLOW)
  guard/        policy, queries, Guard service (+ certificate), contamination, readjudicate
  memory/       shared-memory retrieval (hides quarantined memories)
  warden/       analyses, MCP server, agent/planners, chokepoints, remediation, citations, CLI
  demo/         attack.py (primary), extended.py, worlds.py, llm_run.py (record/replay),
                acme_guard.py (guard_demo), acme_warden.py (Warden CLI seed incident)
  console/      UI read models, agent-influence projection, demo/Warden runners
  api/          FastAPI app; routes: recorder, guard, console; public_demo.py
  seeds/        synthetic Acme tenant seed (scripts/seed_acme.py, scripts/guard_demo.py)
bench/          benchmark generators, baselines, runners and committed results
frontend/       React + Vite + TypeScript console (src/pages, src/components, e2e/) and docs site (src/docs)
scripts/        attack_demo.py, guard_demo.py, warden_demo.py, seed_acme.py,
                record_llm_run.py, export_ui_fixtures.py
tests/          unit, integration, guard, warden, console
docs/           graph-model.md, guard.md, warden.md, screenshots/ (the docs site lives in frontend/src/docs)
```

## Acknowledgements

- **[Claude Code](https://www.anthropic.com/claude-code)** (Anthropic): pair-programming,
  design reviews and help with the docs throughout the build.
- **[ChatGPT](https://chatgpt.com)** (OpenAI): brainstorming, research and second opinions.
- **Harvard's course on self-improving AI models**: the ideas on agents that learn from
  and act on their own memory that shaped the threat model behind Custody.
- **[FalkorDB](https://www.falkordb.com)**: the graph database at the core of Custody, and
  **falkordblite** for the embedded mode that powers the hosted demo.
- **[Model Context Protocol](https://modelcontextprotocol.io)**: the open standard the
  Warden uses to expose its graph tools.
- **[Render](https://render.com)**: hosting for the public demo.
- Open-source projects this is built on: [FastAPI](https://fastapi.tiangolo.com),
  [Pydantic](https://docs.pydantic.dev), [React](https://react.dev),
  [Vite](https://vite.dev), [react-force-graph](https://github.com/vasturiano/react-force-graph),
  [Vitest](https://vitest.dev), [Playwright](https://playwright.dev) and
  [pytest](https://pytest.org).
