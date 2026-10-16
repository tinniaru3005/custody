# Custody documentation

Custody records where every piece of information in a team of AI agents came from, and checks that record before any agent does something outbound or irreversible.

Agent teams share memory. A research agent reads a web page and writes a note; days later, in a different session, an operations agent recalls that note and acts on it. If the page carried a prompt injection, the instruction now looks like trusted team knowledge. Per-turn filters can't see where it came from, because answering "where did this destination come from?" takes several hops across agents, sessions and memory.

Custody answers that question with a graph:

- The **Recorder** stores every user message, web page, vault read, model output, memory, recall and inter-agent message as a node in a **provenance graph** in [FalkorDB](https://www.falkordb.com), with an edge to everything it was derived from.
- The **Guard** runs deterministic Cypher graph queries over that graph before a side effect happens and returns **ALLOW**, **REQUIRE_HUMAN_APPROVAL** or **BLOCK**, together with the exact path that caused the decision. Verdicts come from a complete traversal; a search that cannot finish fails closed and is never an ALLOW. No language model is involved in the decision.
- The **Warden** is an incident-response agent whose only capabilities are [MCP](https://modelcontextprotocol.io) tools over the graph: trace an untrusted source forward, revoke its trust and re-adjudicate past decisions, rank risky memories, quarantine them and draft disclosures. Its own actions pass through the same Guard.

<figure class="diagram">
<svg viewBox="0 0 760 270" role="img" aria-labelledby="ov-t ov-d">
<title id="ov-t">How Custody fits around an agent team</title>
<desc id="ov-d">Agents record data through the Recorder into the FalkorDB provenance graph. Before an action runs, the Guard queries the graph and returns a verdict. The Warden investigates the same graph through MCP tools, and its actions are also checked by the Guard.</desc>
<defs><marker id="ov-a" viewBox="0 0 8 8" refX="7" refY="4" markerWidth="8" markerHeight="8" orient="auto-start-reverse"><path class="dg-arrow" d="M0,0 L8,4 L0,8 z"/></marker></defs>
<rect class="dg-box" x="20" y="30" width="170" height="86" rx="10"/>
<text class="dg-h" x="36" y="56">Your agents</text>
<text class="dg-m" x="36" y="76">read pages, call models,</text>
<text class="dg-m" x="36" y="92">remember, message,</text>
<text class="dg-m" x="36" y="108">propose actions</text>
<rect class="dg-box" x="295" y="30" width="170" height="86" rx="10"/>
<text class="dg-h" x="311" y="56">Recorder</text>
<text class="dg-m" x="311" y="76">the provenance write path</text>
<text class="dg-m" x="311" y="92">every Datum + its parents</text>
<text class="dg-code" x="311" y="108">/record/*</text>
<rect class="dg-db" x="570" y="30" width="170" height="86" rx="10"/>
<text class="dg-h" x="586" y="56">Provenance graph</text>
<text class="dg-m" x="586" y="76">FalkorDB graph per tenant</text>
<text class="dg-m" x="586" y="92">lineage is append-only</text>
<text class="dg-code" x="586" y="108">custody:&lt;tenant&gt;</text>
<rect class="dg-box" x="295" y="160" width="170" height="86" rx="10"/>
<text class="dg-h" x="311" y="186">Guard</text>
<text class="dg-m" x="311" y="206">Cypher queries + static</text>
<text class="dg-m" x="311" y="222">policy, no LLM</text>
<text class="dg-code" x="311" y="238">ALLOW · APPROVAL · BLOCK</text>
<rect class="dg-box" x="570" y="160" width="170" height="86" rx="10"/>
<text class="dg-h" x="586" y="186">Warden</text>
<text class="dg-m" x="586" y="206">MCP tools: trace,</text>
<text class="dg-m" x="586" y="222">rank, quarantine,</text>
<text class="dg-m" x="586" y="238">draft disclosures</text>
<path class="dg-line" d="M190 73 H289" marker-end="url(#ov-a)"/>
<text class="dg-m" x="205" y="66">record</text>
<path class="dg-line" d="M465 73 H564" marker-end="url(#ov-a)"/>
<text class="dg-m" x="490" y="66">write</text>
<path class="dg-line" d="M105 116 V203 H289" marker-end="url(#ov-a)"/>
<text class="dg-m" x="118" y="196">propose action</text>
<path class="dg-line" d="M380 160 V138 H600 V122" marker-end="url(#ov-a)"/>
<text class="dg-m" x="392" y="153">read-only queries</text>
<path class="dg-line" d="M680 160 V122" marker-end="url(#ov-a)"/>
<path class="dg-line" d="M570 222 H471" marker-end="url(#ov-a)"/>
<text class="dg-m" x="482" y="240">its actions too</text>
</svg>
<figcaption>Agents record what they see and produce; the Guard decides from the graph before anything leaves; the Warden investigates the same graph.</figcaption>
</figure>

## What the demo shows

The console ships with a synthetic company, **Acme Robotics**, and a scripted attack. On simulated Day 1, a research agent reads a vendor page with a hidden instruction and saves the attacker's URL to shared memory. On Day 4, an operations agent recalls that memory while rotating an API key. Its post of the key to the internal Slack channel is **allowed**; its upload of the key to the attacker's URL is **blocked**, and the console shows the path back to the vendor page.

![Attack demo at step 7: the timeline, the blocked upload and the provenance path back to the vendor page](demo-overview.webp "The attack demo after the story has played: step 5 allowed, step 6 blocked, step 7 shows the path that explains the block.")

> [!SIMULATED]
> Acme Robotics is a synthetic company. The vendor web page, email, Slack, the vault, GitHub and the attacker's upload server are simulated in-process: no network request is made and executed actions go to an in-memory outbox. "Day 1" and "Day 4" are sessions on a simulated clock, and the agents follow scripted flows. A language model is only called if you give the Warden an `ANTHROPIC_API_KEY` or record a real run with `scripts/record_llm_run.py`.

> [!REAL]
> The provenance recording, the FalkorDB graph, every Guard decision and its explanation, the Warden's graph queries and algorithms, and the human approvals written to the graph are real. They run the same code an integration would use.

## Where to start

| If you want to                                          | Read                                                    |
| ------------------------------------------------------- | ------------------------------------------------------- |
| Run the console and the attack on your machine          | [Quickstart](/docs/quickstart)                          |
| Understand what gets recorded and why                   | [Provenance graph](/docs/provenance-graph)              |
| Know exactly when an action is allowed, held or blocked | [Guard](/docs/guard)                                    |
| Investigate and contain an incident                     | [Warden](/docs/warden) and [MCP integration](/docs/mcp) |
| Record your own agents' activity                        | [Recording your own agents](/docs/integrating)          |
| Call the HTTP API                                       | [HTTP API](/docs/api-reference)                         |
| Host Custody, or share a read-only demo                 | [Deployment](/docs/deployment)                          |
| Understand what Custody does not protect against        | [Security model](/docs/security)                        |

## Status and scope

Custody is a working reference implementation, not a hosted product. It has no authentication of its own, ships no connectors to real Slack, email or storage services, and its Guard is only as good as the provenance it is given: an integration that leaves context out of the graph can get an ALLOW it should not have. An ALLOW means only that, relative to the recorded provenance graph, the current Source trust labels (policy inputs, not inferred) and a complete traversal, no untrusted influence path was found; it does not prove the action safe. The [security model](/docs/security) lists these limits in full.
