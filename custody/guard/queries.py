"""The Cypher behind every Guard decision.

All traversals are variable-length (``-[:DERIVED_FROM*0..N]->``) so they cross any number
of LLM turns, memories, recalls, inter-agent messages and sessions. ``N`` is the policy's
``max_depth`` (variable-length bounds cannot be query parameters in Cypher, so it is
clamped to an int and formatted in).

Edges with ``attribution = 'context'`` are never followed: they record that a Datum was
in the model's context, but exact-value attribution showed the value came from elsewhere.
Legacy edges without the property count as ``inherit``.
"""
from __future__ import annotations

FOLLOW = "all(r IN relationships(p) WHERE coalesce(r.attribution, 'inherit') <> 'context')"


def _depth(depth: int) -> int:
    return max(1, min(int(depth), 100))


def integrity_paths(depth: int) -> str:
    """Action -[:ARG {role in $roles}]-> Datum -[:DERIVED_FROM*]-> ... -[:FROM]-> untrusted Source.

    Worst paths first: no endorsed Datum on the path, then no typed (quarantined) Datum,
    then shortest. So if any uncleared path exists it is always within LIMIT.
    """
    return (
        "MATCH (a:Action {id: $aid})-[arg:ARG]->(d:Datum) "
        "WHERE arg.role IN $roles "
        f"MATCH p = (d)-[:DERIVED_FROM*0..{_depth(depth)}]->(x:Datum) "
        f"WHERE {FOLLOW} "
        "MATCH (x)-[:FROM]->(s:Source {trust: 'untrusted'}) "
        "WITH arg.role AS role, d.id AS arg_id, p, s, "
        "     [n IN nodes(p) WHERE n.endorsed = true | n.id] AS endorsed_ids, "
        "     [n IN nodes(p) WHERE n.quarantined = true | n.id] AS typed_ids "
        "RETURN role, arg_id, nodes(p), relationships(p), s, endorsed_ids, typed_ids, "
        "       length(p) AS len "
        "ORDER BY size(endorsed_ids), size(typed_ids), len "
        "LIMIT $limit"
    )


def confidentiality_paths(depth: int) -> str:
    """Action -[:ARG {role not in $roles}]-> Datum -[:DERIVED_FROM*0..]-> Datum {sensitivity:'secret'}."""
    return (
        "MATCH (a:Action {id: $aid})-[arg:ARG]->(d:Datum) "
        "WHERE NOT arg.role IN $roles "
        f"MATCH p = (d)-[:DERIVED_FROM*0..{_depth(depth)}]->(x:Datum {{sensitivity: 'secret'}}) "
        f"WHERE {FOLLOW} "
        "OPTIONAL MATCH (x)-[:FROM]->(s:Source) "
        "RETURN arg.role, d.id, nodes(p), relationships(p), s, length(p) AS len "
        "ORDER BY len "
        "LIMIT $limit"
    )


# Destination binding: does the sink's literal destination equal (by fingerprint) the value
# of a Datum passed as a destination argument? If not, the destination is unattributed.
DESTINATION_BINDING = (
    "MATCH (a:Action {id: $aid}) "
    "OPTIONAL MATCH (a)-[:TO]->(k:Sink) "
    "OPTIONAL MATCH (a)-[arg:ARG]->(d:Datum) WHERE arg.role IN $roles "
    "RETURN k, collect(d.fingerprint), collect(d.id)"
)


# Blocked actions and their destination argument Datums (for the endorse() refusal check,
# which then runs a complete search from them).
BLOCKED_DESTINATIONS = (
    "MATCH (a:Action {status: 'blocked'})-[arg:ARG]->(d:Datum) "
    "WHERE arg.role IN $roles RETURN a.id, collect(d.id)"
)


# Precedent: the same Sink, an earlier action with a secret payload argument, and a human
# REJECTS on that earlier action.
PRECEDENT = (
    "MATCH (cur:Action {id: $aid})-[:TO]->(k:Sink)<-[:TO]-(prev:Action) "
    "WHERE prev.id <> cur.id "
    "MATCH (ap:Approval {verdict: 'rejected'})-[:REJECTS]->(prev) "
    "WHERE coalesce(ap.approver_kind, 'human') = 'human' "
    "MATCH (prev)-[pa:ARG]->(pd:Datum {sensitivity: 'secret'}) WHERE NOT pa.role IN $roles "
    "RETURN prev.id, prev.action_type, ap.id, ap.approver, ap.reason, ap.created_at, k.id, "
    "k.destination, collect(DISTINCT pd.id) ORDER BY ap.created_at LIMIT 5"
)

# Secret-egress endorsement: a Guard-followed ancestor of the destination argument holds
# exactly the sink's destination value and a human ENDORSES it with egress=true.
EGRESS_HIT = ("m.fingerprint IN $fps AND "
              "size([(m)<-[e:ENDORSES {egress: true}]-(ap:Approval) | ap.id]) > 0")
EGRESS_TAIL = "[(m)<-[e:ENDORSES {egress: true}]-(ap:Approval) | ap.id]"


QUERY_NAMES = {
    "integrity": "integrity_paths",
    "confidentiality": "confidentiality_paths",
    "binding": "destination_binding",
}
