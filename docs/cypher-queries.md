# Cypher queries and graph algorithms

Every query Custody runs against FalkorDB, grouped by the decision or view it serves. The
queries are quoted from the code (Python f-string placeholders resolved: `{S.DATUM}` →
`Datum`, `{depth}` → the configured bound). Labels and relationships are defined in
[graph-model.md](graph-model.md).

| Where | What |
|---|---|
| `custody/graph/traversal.py` | the complete, fail-closed breadth-first search used for every verdict |
| `custody/guard/queries.py` | Guard evidence paths, destination binding, precedent, egress endorsement |
| `custody/graph/repository.py` | the write path and the bounded read API |
| `custody/warden/queries.py` | Warden analyses, `algo.betweenness`, `algo.WCC` |
| `custody/warden/chokepoints.py`, `sandbox.py`, `simulate.py` | chokepoints, `GRAPH.COPY` sandboxes, policy what-ifs |
| `custody/guard/readjudicate.py`, `custody/console/influence.py` | forward re-adjudication, agent-influence view |

Conventions used everywhere:

- **Backwards** in time is `(d)-[:DERIVED_FROM]->(parent)`; forwards is
  `(d)<-[:DERIVED_FROM]-(child)`.
- **Guard-followed edges** skip exact-value-attribution context edges:
  `coalesce(r.attribution, 'inherit') <> 'context'` (or, over a path,
  `all(r IN relationships(p) WHERE coalesce(r.attribution,'inherit') <> 'context')`).
- **Every decision query is read-only** (`GRAPH.RO_QUERY` via `graph.ro_query`) and carries
  a server-side timeout, so a check can neither write nor hang.
- Variable-length bounds cannot be Cypher parameters, so depths are clamped to `1..100` and
  formatted into the query.

## Why graph traversal is the core of Custody

Custody's question is never "does this text look malicious?" but "**is there a chain of
recorded derivations from this action's argument back to an untrusted Source?**" That chain
can cross any number of LLM turns, saved memories, later sessions that recall them, and
messages between agents. It is a reachability question over an unbounded-depth DAG, and the
answer has to be both a yes/no and the path itself as evidence.

FalkorDB makes that the natural shape of the data and the query:

- **The data is the graph.** Every turn, memory, recall and message is a `:Datum` with
  `DERIVED_FROM` edges, so one traversal crosses agents, sessions and time without joins or
  special cases. Trust lives on `:Source` nodes and is evaluated per path at decision time.
- **Index-backed frontier expansion.** Each BFS level is one query that looks up the
  frontier by indexed `id` and expands one hop. Cost is linear in visited nodes and edges
  (3–4.5 ms on dense sessions where path enumeration with `*1..N` times out; see
  [bench/results/sql_compare.md](../bench/results/sql_compare.md)).
- **Paths as first-class results.** Pattern queries return `nodes(p)` / `relationships(p)`,
  which become the evidence shown in the console and cited in every Decision.
- **Server-enforced read-only checks and timeouts** (`GRAPH.RO_QUERY` + per-query timeout)
  make "a decision can't write" and "a slow decision fails closed" properties of the
  database, not of application discipline.
- **Built-in graph algorithms** (`algo.betweenness`, `algo.WCC`) answer the Warden's "which
  memory matters most?" and "which contamination belongs together?" in one call.
- **`GRAPH.COPY`** gives the Warden a disposable clone for what-if analyses that need to
  write (labelling, re-running the Guard under another policy) without touching the tenant.
- **One graph per tenant** (`custody:<tenant>`) isolates tenants and drops them atomically;
  the same code runs on a local server, FalkorDB Cloud and embedded `falkordblite`.

Honest scope: a recursive SQL CTE over the same edges reaches the same verdicts on the
benchmark (330/330). What FalkorDB adds is the property-graph model, path results, the
algorithms, copies and read-only enforcement in one engine. What makes the verdicts sound is
the *complete* traversal below, not any particular engine.

## 1. Complete reachability (every Guard verdict)

`traversal.search()` drives a level-by-level BFS from Python. A visited set makes it
cycle-safe and expands each node once; there is no depth bound by default. Frontiers are
sent in batches of 500 ids.

Start nodes:

```cypher
UNWIND $ids AS i MATCH (m:Datum {id: i}) WHERE <node_ok>
RETURN m.id, <hit>, <tail>
```

One expansion level (backwards; `reverse=True` flips the arrow to walk forwards):

```cypher
UNWIND $ids AS i MATCH (n:Datum {id: i}) WITH n
MATCH (n)-[r:DERIVED_FROM]->(m:Datum)
WHERE <edge_ok> AND <node_ok>
RETURN DISTINCT n.id, m.id, coalesce(r.op, type(r)),
       coalesce(r.attribution, 'inherit'), <hit>, <tail>
```

`WITH n` pins the plan to "index lookup of the frontier, then expand"; without it the
planner can scan every Datum per frontier id.

The searches are this one query with different filters:

| Search | `hit` | `node_ok` / `edge_ok` | Used by |
|---|---|---|---|
| `untrusted_origin` (integrity) | `size([(m)-[:FROM]->(s:Source {trust:'untrusted'}) \| s.id]) > 0` | `coalesce(m.endorsed,false) = false`, and not a typed value whose `max_risk` covers the action (`$risk_rank`); Guard-followed edges | Guard integrity verdict, chokepoints, contamination, Warden, influence view |
| `secret_origin` (confidentiality) | `m.sensitivity = 'secret'` | Guard-followed edges | Guard confidentiality verdict |
| egress endorsement | `m.fingerprint IN $fps AND size([(m)<-[e:ENDORSES {egress: true}]-(ap:Approval) \| ap.id]) > 0` | Guard-followed edges | clearing an approved secret egress |
| `ancestor_graph` | `false` (explore all) | none: every edge, context edges included | Provenance Completeness Certificate, Warden citations |
| forward walk (`reverse=True`) | `false` | none | trust revocation → re-adjudication; console taint view |
| `path_to` | `m.id = $to` or `FROM` a Source with that id | none | `path-to` views |

Outcome: `PATH_FOUND` (witness path attached), `NO_PATH` (graph exhausted) or
`INDETERMINATE` (node limit 100 000, 2 s budget, explicit depth limit or query error). The
Guard treats `INDETERMINATE` as a violation. After a complete `ancestor_graph` walk, the
certificate reads the roots of every visited Datum:

```cypher
MATCH (d:Datum) WHERE d.id IN $ids
OPTIONAL MATCH (d)-[:FROM]->(s:Source)
RETURN d.id, coalesce(d.endorsed, false), coalesce(d.quarantined, false),
       coalesce(d.max_risk, 'low'), s.id, s.kind, s.trust, d.kind, d.coverage
```

## 2. Guard evidence and policy queries (`custody/guard/queries.py`)

The evidence queries are depth-bounded (`GuardPolicy.max_depth`, default 25) and only
supply readable paths. If they find no violating path, the verdict still comes from the
complete search in section 1, and a path found beyond the bound is surfaced from its witness.

**Integrity evidence**: argument → … → untrusted Source, worst paths first (no endorsed
Datum, then no typed Datum, then shortest), so any uncleared path is within `LIMIT`:

```cypher
MATCH (a:Action {id: $aid})-[arg:ARG]->(d:Datum)
WHERE arg.role IN $roles
MATCH p = (d)-[:DERIVED_FROM*0..25]->(x:Datum)
WHERE all(r IN relationships(p) WHERE coalesce(r.attribution, 'inherit') <> 'context')
MATCH (x)-[:FROM]->(s:Source {trust: 'untrusted'})
WITH arg.role AS role, d.id AS arg_id, p, s,
     [n IN nodes(p) WHERE n.endorsed = true | n.id] AS endorsed_ids,
     [n IN nodes(p) WHERE n.quarantined = true | n.id] AS typed_ids
RETURN role, arg_id, nodes(p), relationships(p), s, endorsed_ids, typed_ids,
       length(p) AS len
ORDER BY size(endorsed_ids), size(typed_ids), len
LIMIT $limit
```

`$roles` are the destination roles of the action. **Confidentiality evidence** is the
mirror image over the non-destination arguments:

```cypher
MATCH (a:Action {id: $aid})-[arg:ARG]->(d:Datum)
WHERE NOT arg.role IN $roles
MATCH p = (d)-[:DERIVED_FROM*0..25]->(x:Datum {sensitivity: 'secret'})
WHERE all(r IN relationships(p) WHERE coalesce(r.attribution, 'inherit') <> 'context')
OPTIONAL MATCH (x)-[:FROM]->(s:Source)
RETURN arg.role, d.id, nodes(p), relationships(p), s, length(p) AS len
ORDER BY len
LIMIT $limit
```

**Destination binding**: the sink's literal destination must equal (by fingerprint) a
destination-argument Datum; otherwise the destination is unattributed:

```cypher
MATCH (a:Action {id: $aid})
OPTIONAL MATCH (a)-[:TO]->(k:Sink)
OPTIONAL MATCH (a)-[arg:ARG]->(d:Datum) WHERE arg.role IN $roles
RETURN k, collect(d.fingerprint), collect(d.id)
```

**Precedent escalation**: a human rejected an earlier action to the same Sink that carried
a secret, so REQUIRE_HUMAN_APPROVAL escalates to BLOCK:

```cypher
MATCH (cur:Action {id: $aid})-[:TO]->(k:Sink)<-[:TO]-(prev:Action)
WHERE prev.id <> cur.id
MATCH (ap:Approval {verdict: 'rejected'})-[:REJECTS]->(prev)
WHERE coalesce(ap.approver_kind, 'human') = 'human'
MATCH (prev)-[pa:ARG]->(pd:Datum {sensitivity: 'secret'}) WHERE NOT pa.role IN $roles
RETURN prev.id, prev.action_type, ap.id, ap.approver, ap.reason, ap.created_at, k.id,
       k.destination, collect(DISTINCT pd.id) ORDER BY ap.created_at LIMIT 5
```

**Endorsement refusal**: before a human endorsement is recorded, the Guard lists blocked
actions' destination Datums and runs a complete search from them (`hit = m.id IN
$endorse_ids`). If any Datum to be endorsed feeds a blocked action, or the search is
incomplete, the endorsement is refused, so a lethal-trifecta BLOCK can't be laundered into
an approvable action:

```cypher
MATCH (a:Action {status: 'blocked'})-[arg:ARG]->(d:Datum)
WHERE arg.role IN $roles RETURN a.id, collect(d.id)
```

## 3. Writes: recording provenance (`custody/graph/repository.py`)

Every write is bracketed by graph-version counters, which the certificate uses to detect a
concurrent write:

```cypher
MERGE (m:GraphMeta {id: 'graph'}) SET m.started = coalesce(m.started, 0) + 1
// … the write …
MERGE (m:GraphMeta {id: 'graph'}) SET m.finished = coalesce(m.finished, 0) + 1
```

A Datum, its one `FROM` edge and its `DERIVED_FROM` edges are written in one query, so a
Datum never exists without its provenance (extra labels such as `:Memory` are added to
`:Datum`):

```cypher
MATCH (s:Source {id: $source_id})
CREATE (d:Datum {…})
CREATE (d)-[:FROM {created_at: $now}]->(s)
WITH d
UNWIND $parents AS par
MATCH (p:Datum {id: par.id})
CREATE (d)-[:DERIVED_FROM {op: par.op, attribution: par.attr, created_at: $now}]->(p)
RETURN count(p)
```

Sources are merged, first write wins:

```cypher
MERGE (s:Source {id: $id})
ON CREATE SET s.kind = $kind, s.trust = $trust, s.metadata = $metadata, s.created_at = $now
RETURN s
```

Actions are created with their `ARG` edges (`UNWIND $args … CREATE (a)-[:ARG {role}]->(d)`)
and a merged `(:Sink)` via `TO`. Approvals create `ENDORSES`, `APPROVES {checks}` or
`REJECTS` edges; each Guard evaluation writes `(:Decision)-[:EVALUATES]->(:Action)`.
Trust revocation is the one mutation of a Source, kept next to an audit node:

```cypher
MATCH (s:Source {id: $id})
WITH s, s.trust AS before
SET s.trust_original = coalesce(s.trust_original, s.trust), s.trust = 'untrusted',
    s.revoked_at = $at, s.revoked_by = $by
CREATE (r:TrustRevocation {id: $rid, source_id: $id, revoked_by: $by,
        reason: $reason, created_at: $at, trust_before: before})-[:REVOKES]->(s)
RETURN before
```

Indexes (`custody/graph/schema.py`, created idempotently at startup): range indexes on
`Source(id, kind)`, `Datum(id, kind, session_id, fingerprint)`, `Action(id, status)`,
`Sink(id, destination)`, `Approval(id)`, `Decision(id, action_id)`, `Quarantine(id)` and
`Run(kind)`.

## 4. Bounded read views (people, not policy)

Bounded by `CUSTODY_MAX_TRACE_DEPTH` (25). `lineage()` uses `traversal.ancestors()` and then
reads each ancestor with its Source. Concrete paths between two nodes:

```cypher
MATCH (a:Datum {id: $from}), (b {id: $to})
MATCH p = (a)-[:DERIVED_FROM|FROM*1..25]->(b)
RETURN [n IN nodes(p) | n.id], [r IN relationships(p) | coalesce(r.op, type(r))],
       length(p) AS len
ORDER BY len LIMIT $limit
```

## 5. Warden analyses (`custody/warden/queries.py`)

All read-only on the live graph. Depths use `CUSTODY_MAX_TRACE_DEPTH`.

| MCP tool | Query |
|---|---|
| `find_sources` | `MATCH (s:Source) WHERE ($kind IS NULL OR s.kind = $kind) AND ($trust IS NULL OR s.trust = $trust) OPTIONAL MATCH (s)<-[:FROM]-(o:Datum) …`, plus a downstream count per source |
| `trace_back` | `ancestors_of_action`: every ancestor of every argument with min depth, whether a Guard-followed path reaches it, and its Source; `action_paths` for concrete paths |
| `trace_forward` | `forward`: everything downstream of a Source's origin Datums |
| `rank_risky_memories` | `memory_downstream` + `algo.betweenness` (below) |
| `cluster_incidents` | `contaminated` pairs, then `algo.WCC` on a `GRAPH.COPY` sandbox (below) |
| `simulate_policy` | the Guard re-run on a sandbox; `actions_depending_on_recalls` for hypothetical quarantines |
| `find_chokepoints` | section 6 |

Forward influence, with direct vs context-only influence:

```cypher
MATCH (o:Datum) WHERE o.id IN $ids
MATCH p = (o)<-[:DERIVED_FROM*0..25]-(d:Datum)
WITH d, min(length(p)) AS depth,
     max(CASE WHEN all(r IN relationships(p)
              WHERE coalesce(r.attribution,'inherit') <> 'context') THEN 1 ELSE 0 END) AS direct
RETURN d, depth, direct ORDER BY depth, d.created_at
```

Contamination (Datums downstream of untrusted Sources, Warden's own artefacts excluded):

```cypher
MATCH (s:Source {trust: 'untrusted'})<-[:FROM]-(o:Datum)
MATCH p = (o)<-[:DERIVED_FROM*0..25]-(d:Datum)
WHERE all(r IN relationships(p) WHERE coalesce(r.attribution,'inherit') <> 'context')
  AND coalesce(d.agent, '') <> $warden
RETURN DISTINCT s.id, d.id
```

### Graph algorithm: betweenness centrality

Memories that sit on many shortest paths between Sources, Datums and Actions are the ones
through which influence spreads, so they rank highest for quarantine:

```cypher
CALL algo.betweenness({nodeLabels: ['Datum', 'Action', 'Source'],
                       relationshipTypes: ['DERIVED_FROM', 'ARG', 'FROM']})
YIELD node, score
WHERE 'Memory' IN labels(node)
RETURN node.id, score
```

If the server lacks `algo.betweenness`, ranking falls back to downstream reach and the
result says so.

### Graph algorithm: weakly connected components

Contamination that shares any Datum, Source or Action belongs to one incident. On a
`GRAPH.COPY` clone, the contaminated nodes are labelled and WCC runs on that induced
subgraph:

```cypher
// sandbox clone only
MATCH (n) WHERE (n:Datum OR n:Source OR n:Action) AND n.id IN $ids
SET n:Contaminated RETURN count(n)

CALL algo.WCC({nodeLabels: ['Contaminated'],
               relationshipTypes: ['DERIVED_FROM', 'FROM', 'ARG']})
YIELD node, componentId RETURN node.id, componentId
```

If `GRAPH.COPY` or `algo.WCC` is unavailable, clustering uses union-find over the same
Cypher projection and the result names the method used.

### `GRAPH.COPY` sandboxes

`GraphSandbox` copies `custody:<tenant>` to `custody:<tenant>::sandbox::<id>`, runs the
analysis there and deletes the clone. Without `GRAPH.COPY` it routes every query through
`GRAPH.RO_QUERY` on the live graph, so the server rejects any write.

## 6. Chokepoints, re-adjudication and the influence view

**Chokepoints** (`custody/warden/chokepoints.py`): explore the Guard-followed ancestry of
the destination completely (`untrusted_origin` with `hit = false`), keep the subgraph that
reaches an untrusted-origin Datum, count paths through each node, then re-run the real
integrity search with each candidate excluded (`AND NOT m.id IN $exclude`). Only a complete
`NO_PATH` makes a node a chokepoint.

**Retroactive re-adjudication** (`custody/guard/readjudicate.py`): after a trust
revocation, find the Source's Datums, walk forwards completely, and re-run the Guard on
every action with an argument downstream:

```cypher
MATCH (d:Datum)-[:FROM]->(:Source {id: $id}) RETURN d.id
// complete forward BFS (reverse=True) from those ids, then:
MATCH (a:Action)-[r:ARG]->(d:Datum) WHERE d.id IN $ids
RETURN a.id, r.role, d.id ORDER BY a.created_at, a.id
```

If the forward walk is incomplete, the report is refused (the revocation stays).

**Agent-influence view** (`custody/console/influence.py`): taint is a complete forward walk
from every untrusted entry Datum; cross-agent channels are

```cypher
MATCH (c:Datum)-[r:DERIVED_FROM]->(p:Datum)
WHERE c.agent IS NOT NULL AND p.agent IS NOT NULL AND c.agent <> p.agent
RETURN c.id, c.agent, c.session_id, p.id, p.agent, p.session_id, labels(p),
       coalesce(r.attribution, 'inherit'), r.op
```

grouped into "who influenced whom" edges, with each tainted channel's witness path from
`untrusted_origin`.
