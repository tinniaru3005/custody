"""Citation-grounded incident claims for Warden disclosures.

Every factual sentence in a disclosure is a ``CitedClaim``: readable text plus the graph ids
(Action, Sink, Datum, Memory, Message, Source) it rests on. Before a draft is returned,
``verify`` checks each claim:

1. it cites at least one id;
2. every cited id exists in the tenant graph;
3. every cited id belongs to the traced incident: the actions themselves, their sinks, or
   the complete recorded ancestry of their arguments (``traversal.ancestor_graph``: every
   DERIVED_FROM edge, context edges included) and the Sources those Datums come FROM.

Claims that fail are removed and reported in ``rejected_claims`` with the reason. Prose
written by a model (``claims=`` / ``notes=``) goes through the same check: it may phrase
facts, it cannot add facts the graph does not support. The scope is computed, not
remembered: if the ancestry traversal is incomplete, ids outside what was visited are
rejected (fail closed).
"""
from __future__ import annotations

import re
from typing import Dict, List, Optional, Sequence, Set, Tuple

from pydantic import BaseModel, Field

from custody.graph import traversal as T

_LABEL_ORDER = ("Action", "Sink", "Memory", "Recall", "Message", "Typed", "Datum", "Source")
_BRACKETED = re.compile(r"\[([^\[\]]+)\]")


class CitedClaim(BaseModel):
    text: str
    citations: List[str] = Field(default_factory=list)
    origin: str = "warden"                   # warden (deterministic) | model (prose)
    chain: bool = False                      # citations form a provenance path (render →)
    verified: bool = False
    rejected_reason: Optional[str] = None
    rendered: str = ""                       # text + "(Action a42, Sink s9)"


class IncidentScope(BaseModel):
    action_ids: List[str]
    node_ids: Set[str]
    complete: bool
    labels: Dict[str, str] = Field(default_factory=dict)   # id -> display label

    model_config = {"arbitrary_types_allowed": True}


def incident_scope(repo, actions: Sequence, limits: Dict) -> IncidentScope:
    """Everything a disclosure about ``actions`` may cite."""
    ids: Set[str] = set()
    complete = True
    arg_ids: List[str] = []
    for a in actions:
        ids.add(a.id)
        if a.sink is not None and a.sink.id:
            ids.add(a.sink.id)
        arg_ids += [x.datum_id for x in a.args]
    if arg_ids:
        anc = T.ancestor_graph(repo.graph, arg_ids, **limits)
        complete = anc.complete
        ids |= set(anc.depth)
        ids |= {s["id"] for s in anc.sources.values()}
    return IncidentScope(action_ids=[a.id for a in actions], node_ids=ids, complete=complete,
                         labels=_labels(repo, ids))


def _labels(repo, ids) -> Dict[str, str]:
    if not ids:
        return {}
    out = {}
    for nid, labels in repo.graph.ro_query("MATCH (n) WHERE n.id IN $ids RETURN n.id, labels(n)",
                                           {"ids": sorted(ids)}).result_set:
        out[nid] = next((lab for lab in _LABEL_ORDER if lab in labels), labels[0])
    return out


def render(claim: CitedClaim, labels: Dict[str, str]) -> str:
    refs = (" → " if claim.chain else ", ").join(f"{labels.get(c, 'Node')} {c}"
                                                 for c in claim.citations)
    return f"{claim.text} ({refs})" if refs else claim.text


def verify(repo, claims: Sequence[CitedClaim], scope: IncidentScope
           ) -> Tuple[List[CitedClaim], List[CitedClaim]]:
    """(verified, rejected). A claim is kept only if every citation exists and is in scope."""
    cited = {c for cl in claims for c in cl.citations}
    existing = _labels(repo, cited - set(scope.labels))
    labels = {**scope.labels, **existing}
    ok, bad = [], []
    for cl in claims:
        cl = cl.model_copy()
        missing = [c for c in cl.citations if c not in labels]
        outside = [c for c in cl.citations if c in labels and c not in scope.node_ids]
        if not cl.citations:
            cl.rejected_reason = "no citation: every factual claim must cite graph ids"
        elif missing:
            cl.rejected_reason = "cited id(s) do not exist: " + ", ".join(missing)
        elif outside:
            cl.rejected_reason = ("cited id(s) are not part of the traced incident: "
                                  + ", ".join(outside))
        if cl.rejected_reason:
            bad.append(cl)
            continue
        cl.verified = True
        cl.rendered = render(cl, labels)
        ok.append(cl)
    return ok, bad


def claims_from_notes(notes: Optional[str]) -> List[CitedClaim]:
    """Free text from a model: one claim per sentence, citations in square brackets
    ("The page asked agents to copy keys [web:https://…, d_31]."). Sentences without a
    citation become uncited claims and are rejected by ``verify``."""
    if not notes:
        return []
    out = []
    for sent in re.split(r"(?<=[.!?])\s+", notes.strip()):
        if not sent.strip():
            continue
        cites = [c.strip() for grp in _BRACKETED.findall(sent) for c in grp.split(",")
                 if c.strip()]
        text = _BRACKETED.sub("", sent).strip()
        text = re.sub(r"\s+([.!?,;])", r"\1", text)
        text = text.rstrip(" .!?")
        out.append(CitedClaim(text=text, citations=cites, origin="model"))
    return out
