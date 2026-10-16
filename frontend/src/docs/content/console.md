# Console tour

The console is the React app at `/`. It reads the graph through the console API (`/api/tenants/{tenant}/console/*`), plus `/api/health`, the Guard's re-adjudication list and single Datum reads. Its only writes are running and resetting the demo, rebuilding the three worlds, running the Warden, sending an approved disclosure, and the Guard's approve and reject endpoints. In [public-demo mode](/docs/deployment#public-demo-mode) the write controls are hidden or disabled, except **Reset Demo**. Every screenshot on this page was captured from the running app.

The console shows one tenant, `acme` by default (set `VITE_TENANT` at build time to change it). A banner at the top of every page says what is simulated.

![The simulation banner in public-demo mode](public-demo-banner.webp "The banner on every page. In public-demo mode it adds the read-only tag and a Reset Demo button.")

## Dashboard

Counts of checked, allowed, held and blocked actions, active incidents and quarantined memories; one card per agent with a tainted flag when untrusted data reached it; recent actions with their Guard verdict and latency; incidents; and the shared memories, with tainted and quarantined ones marked. On an empty tenant the dashboard instead shows a short introduction and a **Run attack scenario** button (not in public-demo mode).

![The dashboard after the primary demo](dashboard.webp "After the primary demo: two actions checked, one allowed, one blocked, one active incident, and the tainted team-backup-destination memory.")

## Attack demo

One click wipes the tenant and records the seven-step story. The page plays it step by step, says what is simulated in each step, grows the graph as it goes, and ends with the provenance path behind the block. A notice says whether the run was the scripted simulation or a [replay of a recorded run](/docs/demos#recorded-llm-replay), and if so whether the recording came from a real model or a test double. **Reset** empties the tenant (in public-demo mode, **Reset Demo** restores the initial state). Details of each step: [Demo scenarios](/docs/demos#the-primary-attack).

![Step 1 of the attack demo](demo-step1-poisoned-page.webp "Each step explains what happened and labels the simulated parts, here the synthetic vendor page.")

## Three worlds

The same Day-4 request, the same destination bytes and the same key, recorded in three different histories, produce ALLOW, REQUIRE APPROVAL and BLOCK. **Rebuild** records them into a separate graph (`<tenant>-worlds`). See [Three worlds](/docs/demos#three-worlds).

![The Three worlds page](worlds.webp "World A: a pre-approved registry entry (ALLOW). World B: typed by a trusted user, but nobody approved secrets to it (REQUIRE APPROVAL). World C: from the poisoned memory (BLOCK).")

## Provenance graph

Two views, toggled at the top of the page:

- **Nodes**: every Source, Datum, Memory, Recall, Message, Action, Sink, Approval and Quarantine (Decision nodes on request), in a layered or force-directed layout, with a search box, per-type filters and toggles for contamination only, the blocked path and system sources. Trusted, untrusted, secret, quarantined and blocked are distinguished by colour _and_ shape or marker. The path behind the blocked action is animated. Click a node for its metadata and edges; `?focus=<node id>` selects one from a link.
- **Agent influence** (`?view=agents`): the graph collapsed to who influenced whom, derived on every request from `GET …/console/influence`. Channels that carry untrusted content are marked; click a row for the underlying path.

![The node inspector for the untrusted vendor page](graph-inspector.webp "The inspector shows a node's properties and edges. Untrusted content is displayed as inert data.")

![Agent-level influence](graph-agents.webp "Agent influence: where untrusted content entered (the vendor page into Scout) and the channel between agents (Scout's memory, recalled by Ops).")

## Guard decisions

Per action: the verdict, the explanation, the shortest uncleared route drawn as cards, every check with its queries and timings, the lethal-trifecta checklist, the sink classification, the approval option (or why there is none), the latency breakdown, untrusted roots and route independence, chokepoints (for actions that are not allowed), every path the queries returned, and the audit trail of Decisions and human decisions stored in the graph. The decision shown is a fresh Guard check, computed on every view and not stored as a Decision. ALLOW decisions show the completeness certificate, or why none was issued. Reference: [Guard](/docs/guard).

## Approvals

Actions waiting for a human, with the risky path and why approval is needed. **Approve** and **Reject** write `ENDORSES`, `APPROVES` or `REJECTS` relationships into the graph, recorded under the approver name in the field at the top right. After an approval, a decision-flip card shows the new relationship and the Guard's re-run verdict. Blocked actions (lethal trifecta or precedent) are listed without buttons, and the API refuses them too. A held action with no approval option (the provenance search was incomplete) shows the reason instead of buttons. Approved disclosures can then be sent from here; sending runs a fresh Guard check first.

![The Approvals page on the extended scenario](approvals.webp "Two actions wait for a human on the extended scenario: a backup configuration whose destination traces to the vendor page, and the Warden's disclosure.")

![A blocked action on the Approvals page](approvals-blocked.webp "Blocked actions are shown for context but have no Approve or Reject buttons.")

> [!NOTE]
> The approver name is typed into the page. Custody has no login: whoever can reach the console can approve as anyone. Put it behind your own authentication before using it with anything real, or use [public-demo mode](/docs/deployment#public-demo-mode), which refuses approvals.

## Warden

A free-text command, a planner choice (`auto`, `anthropic` or `playbook`), and a report with every MCP tool call rendered readably next to its raw JSON. The page also lists trust re-adjudications. Reference: [Warden](/docs/warden).

## Metrics

Guard latency (median of live re-runs) and its per-query breakdown, provenance path length, sessions and agents crossed, affected memories, agents and actions, blocked actions, a determinism check (re-runs must return identical verdicts, checks and paths), the latencies of the Decisions recorded in the graph, and the Cypher patterns behind each decision. The live re-runs are not stored as Decisions.

![The Metrics page](metrics.webp "Metrics re-checks the blocked action live: 5/5 identical results, a 2-hop path across 2 sessions and 2 agents, and the latency of each query.")

## Documentation

The **Documentation** link at the bottom of the sidebar opens this site at `/docs`. It is part of the same build, needs no backend call, and has its own search (Ctrl K or ⌘ K, or `/`).
