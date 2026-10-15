# Architecture

Custody is one Python process (FastAPI) in front of FalkorDB, plus a React console that the same process can serve. This page maps the components to the code.

<figure class="diagram">
<svg viewBox="0 0 760 430" role="img" aria-labelledby="ar-t ar-d">
<title id="ar-t">Custody components</title>
<desc id="ar-d">The React console calls the FastAPI app under /api. FastAPI hosts the Recorder, Guard and console routes. The agent runtime records through the Recorder and asks the Guard before executing. The console's Warden runner talks to the Warden MCP server in-process; the same server can run standalone over stdio or HTTP. Everything reads and writes one FalkorDB graph per tenant.</desc>
<defs><marker id="ar-a" viewBox="0 0 8 8" refX="7" refY="4" markerWidth="8" markerHeight="8" orient="auto-start-reverse"><path class="dg-arrow" d="M0,0 L8,4 L0,8 z"/></marker></defs>
<rect class="dg-box" x="20" y="16" width="720" height="58" rx="10"/>
<text class="dg-h" x="36" y="40">Console</text>
<text class="dg-m" x="36" y="60">React + Vite + TypeScript · dashboard, attack demo, graph, Guard, approvals, Warden, metrics, docs</text>
<path class="dg-line" d="M380 74 V104" marker-end="url(#ar-a)"/>
<text class="dg-code" x="390" y="94">/api/… (same origin)</text>
<rect class="dg-group" x="20" y="108" width="720" height="128" rx="12"/>
<text class="dg-h" x="36" y="130">FastAPI app</text>
<text class="dg-code" x="560" y="130">custody/api/</text>
<rect class="dg-box" x="36" y="144" width="216" height="76" rx="8"/>
<text class="dg-h" x="50" y="166">Recorder routes</text>
<text class="dg-code" x="50" y="186">/tenants/{t}/record/*</text>
<text class="dg-m" x="50" y="204">the only provenance write path</text>
<rect class="dg-box" x="272" y="144" width="216" height="76" rx="8"/>
<text class="dg-h" x="286" y="166">Guard routes</text>
<text class="dg-code" x="286" y="186">/tenants/{t}/guard/*</text>
<text class="dg-m" x="286" y="204">check · approve · reject · endorse</text>
<rect class="dg-box" x="508" y="144" width="216" height="76" rx="8"/>
<text class="dg-h" x="522" y="166">Console routes</text>
<text class="dg-code" x="522" y="186">/tenants/{t}/console/*</text>
<text class="dg-m" x="522" y="204">read models · demo · Warden runner</text>
<rect class="dg-box" x="20" y="262" width="230" height="78" rx="10"/>
<text class="dg-h" x="36" y="286">Agent runtime</text>
<text class="dg-m" x="36" y="306">sessions record context; tools</text>
<text class="dg-m" x="36" y="322">run only on a Guard ALLOW</text>
<rect class="dg-box" x="265" y="262" width="230" height="78" rx="10"/>
<text class="dg-h" x="281" y="286">Guard</text>
<text class="dg-m" x="281" y="306">complete graph search +</text>
<text class="dg-m" x="281" y="322">static tenant policy, no LLM</text>
<rect class="dg-box" x="510" y="262" width="230" height="78" rx="10"/>
<text class="dg-h" x="526" y="286">Warden MCP server (17 tools)</text>
<text class="dg-m" x="526" y="306">planner: Claude or offline playbook</text>
<text class="dg-m" x="526" y="322">stdio · Streamable HTTP · in-process</text>
<path class="dg-line" d="M250 301 H259" marker-end="url(#ar-a)"/>
<path class="dg-line" d="M510 301 H501" marker-end="url(#ar-a)"/>
<path class="dg-line" d="M380 220 V256" marker-end="url(#ar-a)"/>
<path class="dg-line" d="M616 220 V256" marker-end="url(#ar-a)"/>
<path class="dg-line" d="M144 220 V256" marker-end="url(#ar-a)"/>
<rect class="dg-db" x="230" y="366" width="300" height="50" rx="10"/>
<text class="dg-h" x="246" y="388">FalkorDB</text>
<text class="dg-m" x="246" y="406">one graph per tenant · local, Cloud or embedded</text>
<path class="dg-line" d="M135 340 V391 H224" marker-end="url(#ar-a)"/>
<path class="dg-line" d="M380 340 V360" marker-end="url(#ar-a)"/>
<path class="dg-line" d="M625 340 V391 H536" marker-end="url(#ar-a)"/>
</svg>
<figcaption>All decisions and investigations read the same per-tenant graph. Arrows show calls; every component except the console runs in the API process.</figcaption>
</figure>

## Components

| Component      | Code                                          | Responsibility                                                                                                                                                                         |
| -------------- | --------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Recorder       | [`custody/recorder/`](repo:custody/recorder/) | Writes Sources, Datums, Memories, Recalls, Messages, Actions, Sinks and Approvals. Validates parents before writing, masks secrets, applies exact-value attribution to tool arguments. |
| Graph layer    | [`custody/graph/`](repo:custody/graph/)       | Data model, schema and indexes, Cypher repository, and the complete fail-closed traversal (`traversal.py`).                                                                            |
| Agent runtime  | [`custody/runtime/`](repo:custody/runtime/)   | `AgentRuntime` and `AgentSession`: record everything that enters a session's context and route every tool call through the Guard. Tool execution delivers to an in-memory outbox.      |
| Shared memory  | [`custody/memory/`](repo:custody/memory/)     | Retrieval of memories; hides quarantined ones.                                                                                                                                         |
| Guard          | [`custody/guard/`](repo:custody/guard/)       | Policy, provenance queries, decisions, approvals, certificates, contamination analysis, re-adjudication.                                                                               |
| Warden         | [`custody/warden/`](repo:custody/warden/)     | Investigation analyses, quarantine, remediation, citation-checked disclosures, the MCP server and the agent loop.                                                                      |
| Console API    | [`custody/console/`](repo:custody/console/)   | Read models for the UI, the demo runner and the in-process Warden runner.                                                                                                              |
| Demo scenarios | [`custody/demo/`](repo:custody/demo/)         | The scripted primary story, the extended scenario, three worlds, and the recorded-LLM replay.                                                                                          |
| HTTP app       | [`custody/api/`](repo:custody/api/)           | FastAPI app factory, routes, request schemas, public-demo middleware.                                                                                                                  |
| Console        | [`frontend/`](repo:frontend/)                 | React + Vite + TypeScript UI, this documentation site, unit and Playwright tests.                                                                                                      |

## How an action is decided

1. An agent session records what entered its context: user input, fetched pages, vault reads, recalls, received messages. Each becomes a `Datum` with a `FROM` edge to its `Source`.
2. Each model output, memory and message is recorded with `DERIVED_FROM` edges to everything in the context window.
3. When the model asks for a tool call, each argument becomes a Datum. The Recorder links it to a trusted supplier of the exact same value if one exists (exact-value attribution), and keeps the other context edges marked `attribution: "context"`.
4. The runtime records an `Action` with `ARG` edges to the arguments and a `TO` edge to a `Sink`, then calls `Guard.enforce`.
5. The Guard re-classifies the sink against tenant policy, runs complete reachability searches from the destination and payload arguments, and returns a `GuardDecision`. It appends a `Decision` audit node to the graph.
6. The runtime executes the tool only on `ALLOW`, and re-checks immediately before executing.

Agents that do not use the Python runtime can do steps 1–5 over HTTP and must enforce step 6 themselves; see [Recording your own agents](/docs/integrating).

## HTTP layout

Every API route is also served under `/api`: a small ASGI middleware strips the prefix, so `/api/tenants/acme/console/demo` and `/tenants/acme/console/demo` reach the same handler. The console always uses `/api/...`.

When `CUSTODY_STATIC_DIR` points at a built console (`frontend/dist`), the API also serves it at `/` with a single-page-app fallback: any path that is not an API root (`/tenants`, `/health`, `/swagger`, `/redoc`, `/openapi.json`) and not a file in the build returns `index.html`. That is how deep links such as `/guard/act_…` and `/docs/guard#checks` work in one container.

> [!NOTE]
> FastAPI's interactive API reference is at `/swagger` (also `/api/swagger`), because `/docs` belongs to this documentation site. In public-demo mode `/swagger`, `/redoc` and `/openapi.json` are switched off.

## How FalkorDB is used

- **One graph per tenant** (`custody:<tenant>`), so tenants are isolated and a tenant can be dropped in one call. Tenant slugs must match `[a-z0-9][a-z0-9_-]{0,62}`.
- **Range indexes** on ids, kinds, sessions, fingerprints, action status and sink destination, created idempotently when a graph is first used.
- **Read-only queries** (`GRAPH.RO_QUERY`) for the Guard's checks, so a decision cannot write.
- **Complete level-by-level traversals** for every verdict: one read query per breadth-first level, with a visited set. Variable-length path patterns (`*0..25`) only supply evidence paths and Warden views.
- **Graph algorithms**: `algo.betweenness` to rank risky memories and `algo.WCC` to group contamination into incidents.
- **`GRAPH.COPY` sandboxes** for incident clustering and policy simulation. The clone is deleted afterwards; if the server refuses `GRAPH.COPY`, Custody falls back to read-only queries on the live graph and says so in the result.

## Repository layout

```text
custody/
  api/          FastAPI app; routes: recorder, guard, console; public_demo.py
  console/      UI read models, demo and Warden runners, agent-influence view
  demo/         attack.py (primary story), extended.py, worlds.py, llm_run.py
  graph/        model, schema, repository (Cypher), traversal.py (complete search)
  guard/        policy, queries, Guard service, certificates, re-adjudication
  memory/       shared-memory retrieval (hides quarantined memories)
  recorder/     the provenance write path, exact-value attribution, typed reader
  runtime/      agent sessions and the tool lifecycle (simulated outbox)
  seeds/        the synthetic Acme Robotics tenant
  warden/       analyses, remediation, MCP server, agent, CLI
bench/          benchmark generators, baselines, runners and committed results
frontend/       React console (src/pages, src/components), docs site (src/docs), e2e/
scripts/        attack_demo.py, guard_demo.py, warden_demo.py, record_llm_run.py, …
tests/          unit, integration, guard, warden, console
docs/           graph-model.md, guard.md, warden.md, screenshots/
```
