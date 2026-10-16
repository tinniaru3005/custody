# MCP integration

The Warden's capabilities are exposed as an [MCP](https://modelcontextprotocol.io) server named `custody-warden`, bound to one tenant's graph. Any MCP client can use it: the Warden's own agent loop, Claude Desktop, Claude Code, the MCP Inspector, or another agent framework that wants the Guard's verdict before executing an action.

Code: [`custody/warden/mcp_server.py`](repo:custody/warden/mcp_server.py). It needs the `warden` extra (MCP Python SDK v2).

## Run the server

```bash title="stdio (for desktop clients)"
python -m custody.warden serve --tenant acme
```

```bash title="Streamable HTTP on http://127.0.0.1:8765/mcp"
python -m custody.warden serve --tenant acme --transport streamable-http --port 8765
```

| Flag               | Default             | Meaning                                                                                              |
| ------------------ | ------------------- | ---------------------------------------------------------------------------------------------------- |
| `--tenant`         | required            | the tenant whose graph the tools read and write                                                      |
| `--transport`      | `stdio`             | `stdio`, `streamable-http` or `sse`                                                                  |
| `--host`, `--port` | `127.0.0.1`, `8765` | for the HTTP transports                                                                              |
| `--seed-demo`      | off                 | load the Warden seed incident if the tenant has no actions yet (not the extended scenario)           |
| `--policy`         | the tenant's own    | a registered policy name, or `default`; with `--seed-demo` and no `--policy` the Acme policy is used |
| `--operator`       | `security-operator` | the human identity recorded for `begin_investigation`                                                |

`--seed-demo` loads a small Acme incident built for the Warden ([`custody/demo/acme_warden.py`](repo:custody/demo/acme_warden.py)); `python -m custody.warden seed --tenant acme [--reset]` loads the same incident without starting a server. The console's [extended scenario](/docs/demos#the-extended-scenario) is a different dataset.

The server connects to FalkorDB with the same `CUSTODY_*` settings as the API (see [Configuration](/docs/configuration)). Logs go to stderr, because stdout is the stdio channel.

> [!TIP]
> When the API, the MCP server and the command-line tools should all see the same graph, run a FalkorDB server (Docker or Cloud) rather than an embedded database file.

## Tools

17 tools. Read-only tools are annotated `readOnlyHint: true`. Containment, remediation and disclosure go through recorded, Guard-checked actions; `begin_investigation` and `draft_disclosure` record Datums, and `check_action` records a Decision. Results are typed pydantic models, published as `outputSchema`.

| Tool                                                | Kind                   | What it does                                                                                                                                                |
| --------------------------------------------------- | ---------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `begin_investigation(request)`                      | records                | Records the operator's request as trusted user input; every Warden action derives from it. The agent runner calls it.                                       |
| `find_sources(query?, kind?, trust?, limit?)`       | read                   | Finds Sources by id, URL or content; untrusted sources with the most downstream influence first.                                                            |
| `trace_back(action_id)`                             | read                   | Paths from each argument of an action to its Sources, the memories, recalls and messages crossed, and the latest Guard decision.                            |
| `trace_forward(source_id)`                          | read                   | Everything a Source (or Datum) reached: derived data, memories, recalls, messages, actions; which actions executed externally, were blocked or are pending. |
| `find_chokepoints(action_id)`                       | read                   | Which single node breaks every recorded untrusted path into the action, verified by a complete re-search. A per-node what-if, not a min-cut.                |
| `check_action(action_id)`                           | read + audit           | The Guard as a service. See [below](#the-guard-over-mcp).                                                                                                   |
| `explain_decision(action_id, decision_id?)`         | read                   | A recorded Decision next to the same Guard re-run on today's graph, with `matches_recorded`.                                                                |
| `why_allowed(action_id)`                            | read                   | The action's completeness certificate and a fixed-template rendering of its evidence; no model-written text.                                                |
| `rank_risky_memories(limit?, include_quarantined?)` | read                   | Memories ranked by taint × reach plus `algo.betweenness`.                                                                                                   |
| `cluster_incidents()`                               | read (sandbox)         | Incidents via `algo.WCC` on a `GRAPH.COPY` sandbox, with severity.                                                                                          |
| `simulate_policy(policy)`                           | read (sandbox)         | Re-runs the Guard under a hypothetical policy on a `GRAPH.COPY` clone.                                                                                      |
| `quarantine(memory_ids, reason?, incident_id?)`     | Guard-checked action   | Records `quarantine_memory`; executes only on ALLOW.                                                                                                        |
| `revoke_source_trust(source_id, reason?)`           | Guard-checked action   | Marks a Source untrusted and re-adjudicates history; executes on ALLOW.                                                                                     |
| `propose_loosening(kind, targets, reason?)`         | Guard-checked proposal | Unquarantine, endorse, restore trust or weaken a restriction; always waits for a human.                                                                     |
| `draft_disclosure(action_ids, notes?, claims?)`     | records a draft        | Citation-checked notice per external recipient; nothing is sent.                                                                                            |
| `propose_disclosure(draft_id)`                      | Guard-checked action   | Records `send_disclosure` (email drafts only); the Guard holds it for human review, or blocks it.                                                           |
| `send_approved_disclosure(action_id)`               | Guard-checked action   | Sends (to the in-memory outbox) only after a human approval **and** a fresh Guard ALLOW.                                                                    |

There is deliberately no approval tool. Approval is a human act: the console's Approvals page, `POST /tenants/{t}/guard/actions/{id}/approve`, or `python -m custody.warden approve` (disclosures only). The Guard refuses approvers that are not human or whose name starts with `system:`. A loosening remediation approved by a human is executed only from Python (`Warden.execute_approved_remediation`), not over MCP.

## Connect a client

### Claude Desktop

Add the server to `claude_desktop_config.json` (Settings → Developer → Edit Config). Use absolute paths, since the client does not start in your checkout:

```json title="claude_desktop_config.json"
{
  "mcpServers": {
    "custody-warden": {
      "command": "/absolute/path/to/custody/.venv/bin/python",
      "args": ["-m", "custody.warden", "serve", "--tenant", "acme", "--seed-demo"],
      "env": { "CUSTODY_FALKORDB_HOST": "localhost", "CUSTODY_FALKORDB_PORT": "6379" }
    }
  }
}
```

### Claude Code

```bash title="stdio"
claude mcp add --transport stdio --env CUSTODY_FALKORDB_HOST=localhost \
  custody-warden -- /absolute/path/to/custody/.venv/bin/python -m custody.warden serve --tenant acme
```

```bash title="Streamable HTTP (server already running)"
claude mcp add --transport http custody-warden http://127.0.0.1:8765/mcp
```

### MCP Inspector

```bash title="Terminal"
npx @modelcontextprotocol/inspector .venv/bin/python -m custody.warden serve --tenant acme --seed-demo
```

### The Warden agent against a running server

```bash title="Terminal"
python -m custody.warden agent --tenant acme --mcp-url http://127.0.0.1:8765/mcp \
  "That vendor page was malicious. Clean it up."
```

## The Guard over MCP

`check_action` and `explain_decision` let any MCP-speaking agent framework ask Custody for a verdict on an action it recorded through the [Recorder API](/docs/integrating) before executing it. Both are thin adapters over the same `Guard` the runtime and the HTTP API use; no policy logic lives in the MCP layer.

`check_action` returns `verdict` (`ALLOW`, `REQUIRE_APPROVAL` or `BLOCK`; `REQUIRE_APPROVAL` is the MCP results' short form of the Guard's `REQUIRE_HUMAN_APPROVAL`), `fail_closed` (true when an incomplete search made it non-ALLOW) with the indeterminate checks, the triggered checks, the per-check search outcome (`PATH_FOUND`, `NO_PATH` or `INDETERMINATE`), evidence paths, untrusted sources, the sink classification, approval options, the contamination explanation and, on ALLOW, a certificate summary (claim, root Sources with trust labels, strength, provenance coverage, certificate id). A fail-closed `REQUIRE_APPROVAL` offers no approval. It writes a Decision audit node and never changes the action's status or executes anything. `explain_decision` is read-only and errors if the action was never checked; a later verdict can differ from the recorded one after endorsements, approvals, trust revocations or a policy change.

> [!WARNING]
> **Custody does not enforce anything over MCP.** The caller must execute only on `ALLOW` and must not execute on `BLOCK`, `REQUIRE_APPROVAL` or `fail_closed`. An agent that ignores the verdict is not protected. The in-process runtime is different: `AgentSession.call_tool` executes only on ALLOW.

> [!LIMITATION]
> **The verdict is only as good as the recorded provenance.** If the caller does not record every Datum in the model's context and link each output to all of it, a dangerous path can be missing from the graph and the Guard can return ALLOW. Outputs recorded with `coverage: "REDUCED"` downgrade the certificate. An ALLOW means that, relative to the recorded provenance graph, current trust labels and a complete traversal, no untrusted influence path was found; it does not say the action is safe. Each `check_action` result repeats the enforcement and recording conditions in its `enforcement` field.
