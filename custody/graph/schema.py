"""Graph schema: labels, relationship types and indexes."""
from __future__ import annotations

import logging

from falkordb import Graph

log = logging.getLogger(__name__)

# Node labels
SOURCE = "Source"
DATUM = "Datum"
MEMORY = "Memory"
RECALL = "Recall"
MESSAGE = "Message"
ACTION = "Action"
SINK = "Sink"
APPROVAL = "Approval"
TYPED = "Typed"
DECISION = "Decision"
QUARANTINE = "Quarantine"
REVOCATION = "TrustRevocation"  # a human marked a previously trusted Source compromised
READJUDICATION = "Readjudication"  # a re-run of the Guard on a historical action
QUARANTINE_LIFT = "QuarantineLift"    # a human-approved end of a memory's quarantine
TRUST_RESTORATION = "TrustRestoration"  # a human-approved undo of a trust revocation
GRAPH_META = "GraphMeta"        # write counters: the tenant graph's version (see repository)
RUN = "Run"                    # stored demo / Warden run reports (UI state, not provenance)

DATUM_LABELS = frozenset({DATUM, MEMORY, RECALL, MESSAGE, TYPED})

# Relationship types
FROM = "FROM"                  # (:Datum)-[:FROM]->(:Source)
DERIVED_FROM = "DERIVED_FROM"  # (:Datum)-[:DERIVED_FROM {op}]->(:Datum)
ARG = "ARG"                    # (:Action)-[:ARG {role}]->(:Datum)
TO = "TO"                      # (:Action)-[:TO]->(:Sink)
ENDORSES = "ENDORSES"          # (:Approval)-[:ENDORSES]->(:Datum)
APPROVES = "APPROVES"          # (:Approval)-[:APPROVES {checks}]->(:Action)
REJECTS = "REJECTS"            # (:Approval {verdict:"rejected"})-[:REJECTS]->(:Action)
EVALUATES = "EVALUATES"        # (:Decision)-[:EVALUATES]->(:Action)   Guard audit trail
QUARANTINES = "QUARANTINES"    # (:Quarantine)-[:QUARANTINES]->(:Datum:Memory)  Warden containment
REVOKES = "REVOKES"            # (:TrustRevocation)-[:REVOKES]->(:Source)
READJUDICATES = "READJUDICATES"  # (:Readjudication)-[:READJUDICATES]->(:Action)
PRODUCED = "PRODUCED"          # (:TrustRevocation)-[:PRODUCED]->(:Readjudication)
VIA = "VIA"                    # (:Quarantine)-[:VIA]->(:Action)  the Guard-checked action
LIFTS = "LIFTS"                # (:QuarantineLift)-[:LIFTS]->(:Datum:Memory)
RESTORES = "RESTORES"          # (:TrustRestoration)-[:RESTORES]->(:Source)

# (label, property) range indexes
INDEXES = [
    (SOURCE, "id"),
    (SOURCE, "kind"),
    (DATUM, "id"),
    (DATUM, "kind"),
    (DATUM, "session_id"),
    (DATUM, "fingerprint"),
    (ACTION, "id"),
    (ACTION, "status"),
    (SINK, "id"),
    (SINK, "destination"),
    (APPROVAL, "id"),
    (DECISION, "id"),
    (DECISION, "action_id"),
    (QUARANTINE, "id"),
    (RUN, "kind"),
]


def ensure_schema(graph: Graph) -> None:
    """Create indexes idempotently. Safe to call on every startup."""
    for label, prop in INDEXES:
        try:
            graph.create_node_range_index(label, prop)
        except Exception as exc:  # already indexed
            if "already indexed" not in str(exc).lower():
                log.warning("could not create index %s(%s): %s", label, prop, exc)
