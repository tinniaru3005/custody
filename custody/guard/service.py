"""The Guard: a deterministic policy over provenance.

No model is consulted. Every decision is a pure function of:
  1. facts returned by the Cypher queries in ``custody.guard.queries``, and
  2. the static tenant ``GuardPolicy`` (which actions are guarded, which sinks are internal).

Checks, run before any outbound or irreversible action:

  INTEGRITY        the destination traces (DERIVED_FROM*, then FROM) to an untrusted Source
                   with no endorsed Datum on that path — or the sink's literal destination
                   is not bound to any recorded destination Datum.
  CONFIDENTIALITY  a non-destination argument (payload) traces to a Datum with
                   sensitivity 'secret' AND the sink is external.
  LETHAL TRIFECTA  integrity violated AND payload secret AND sink external.
  HUMAN REVIEW     the action type's policy has ``human_review`` (e.g. Warden's
                   ``send_disclosure``): an explicit human approval is always required.

Policy:  nothing → ALLOW;  integrity or confidentiality → REQUIRE_HUMAN_APPROVAL;
         lethal trifecta → BLOCK (no approval option, ever).

Completeness: the verdict for integrity and confidentiality comes from a complete
reachability search (``custody.graph.traversal``), not from the depth-bounded path queries
(those only supply evidence). Each search ends PATH_FOUND, NO_PATH or INDETERMINATE.
A check passes only on NO_PATH (``path_found=False`` and ``search_complete=True``).
INDETERMINATE (depth/node limit, timeout, query error) is treated as a violation, so an
incomplete search can never yield ALLOW, and a possible lethal trifecta is a BLOCK.

Monotonicity: the graph is append-only and new Datums only point at older ones, so an
existing Datum's ancestry never grows. Approvals can only clear paths. A decision can
therefore only become more permissive through explicit human approval, never through
agent activity.

Threat model: explicit data flow recorded in the graph. Implicit flows through the
model's internal reasoning (e.g. an untrusted page influencing *which* trusted value the
model picks) are out of scope; see docs/guard.md.
"""
from __future__ import annotations

import hashlib
import json
import time
from typing import Any, Dict, List, Optional, Set, Tuple
from collections.abc import Iterable, Sequence

from custody.graph.model import (
    ActionRecord,
    ActionStatus,
    MODEL_OUTPUT_KINDS,
    ApprovalRecord,
    ProvenanceCoverage,
    RiskTier,
    SinkRecord,
    fingerprint,
    load_metadata,
    new_id,
    utcnow_iso,
)
from custody.graph import traversal as T
from custody.graph.repository import GraphVersion
from custody.graph.traversal import ProvenanceSearch
from custody.guard import contamination as C
from custody.guard import queries as Q
from custody.guard.models import (
    ApprovalOption,
    ApprovalRefused,
    CheckName,
    CheckResult,
    ContaminationReport,
    GuardDecision,
    PathEvidence,
    PathNode,
    Precedent,
    ProvenanceCertificate,
    RootRoute,
    RootSource,
    SinkInfo,
    SourceInfo,
    Verdict,
)
from custody.guard.policy import DEFAULT_POLICY, GuardPolicy
from custody.recorder.service import Recorder

_RISK_RANK = {RiskTier.LOW.value: 0, RiskTier.HIGH.value: 1}
# statuses from which the Guard may (re)set the lifecycle status
_OPEN_STATUSES = {ActionStatus.PROPOSED, ActionStatus.PENDING_APPROVAL, ActionStatus.APPROVED}
_TERMINAL_STATUSES = {ActionStatus.BLOCKED, ActionStatus.REJECTED, ActionStatus.EXECUTED,
                      ActionStatus.FAILED}


def _ms(t0: float) -> float:
    return round((time.perf_counter() - t0) * 1000, 3)


def _path_node(node: Any) -> PathNode:
    p = node.properties
    labels = list(node.labels)
    if "Source" in labels:
        return PathNode(id=p["id"], labels=labels, kind=p.get("kind"), trust=p.get("trust"),
                        preview=load_metadata(p.get("metadata")).get("url")
                        or load_metadata(p.get("metadata")).get("path"))
    return PathNode(
        id=p["id"], labels=sorted(labels, key=lambda l: (l != "Datum", l)), kind=p.get("kind"),
        agent=p.get("agent"), session_id=p.get("session_id"), preview=p.get("preview"),
        sensitivity=p.get("sensitivity"), endorsed=bool(p.get("endorsed", False)),
        quarantined=bool(p.get("quarantined", False)),
    )


def _render(action_id: str, role: str, nodes: List[PathNode], ops: List[str]) -> str:
    def label(n: PathNode) -> str:
        if "Source" in n.labels:
            return f"{n.id} [{n.trust}]"
        bits = [n.kind or "?"]
        if n.agent:
            bits.append(n.agent + (f"@{n.session_id}" if n.session_id else ""))
        flags = (" ENDORSED" if n.endorsed else "") + (" TYPED" if n.quarantined else "") + \
                (" SECRET" if n.sensitivity == "secret" else "")
        return f"{n.id} ({' · '.join(bits)}){flags}"

    out = f"{action_id} ={role}=> {label(nodes[0])}"
    for op, n in zip(ops, nodes[1:]):
        out += f" -{op}-> {label(n)}"
    return out


class Guard:
    def __init__(self, recorder: Recorder, policy: GuardPolicy = DEFAULT_POLICY,
                 record_decisions: bool = True) -> None:
        self.recorder = recorder
        self.repo = recorder.repo
        self.policy = policy
        self.record_decisions = record_decisions

    # ================================================================ check
    def check(self, action_id: str) -> GuardDecision:
        t_total = time.perf_counter()
        lat: Dict[str, float] = {}
        pol = self.policy
        roles = sorted(pol.destination_roles)

        t0 = time.perf_counter()
        action = self.repo.get_action(action_id)
        lat["load_action"] = _ms(t0)
        ap = pol.action(action.action_type)
        sink_cls = pol.classify_sink(action.sink)

        if not ap.guarded:
            sink_info = self._sink_info(action.sink, sink_cls, None)
            no_cert = "action is neither outbound nor irreversible: no provenance checks ran"
            skipped = {c.value: CheckResult(name=c, evaluated=False,
                                            detail="action is neither outbound nor irreversible")
                       for c in CheckName}
            lat["total"] = _ms(t_total)
            return self._finish(GuardDecision(
                id=new_id("dec"), action_id=action.id, action_type=action.action_type,
                agent=action.agent, action_status=action.status.value, decision=Verdict.ALLOW,
                explanation=f"{action.action_type} is neither outbound nor irreversible; "
                            "no provenance checks required.",
                checks=skipped, sink=sink_info,
                approval=ApprovalOption(available=False, reason="nothing to approve"),
                latency_ms=lat, policy=f"{pol.name}@{pol.version}", evaluated_at=utcnow_iso(),
                certificate_unavailable=no_cert))

        # graph version at the start: the certificate is tied to it (see _certificate)
        t0 = time.perf_counter()
        version_start = self.repo.graph_version()
        lat["graph_version"] = _ms(t0)

        # ---- action-scoped approvals (APPROVES edges)
        t0 = time.perf_counter()
        approvals = [a for a in self.repo.action_approvals(action.id)
                     if a["approver_kind"] == "human"]
        lat["approvals"] = _ms(t0)
        approved_checks: Dict[str, List[str]] = {}
        for a in approvals:
            for c in a["checks"]:
                approved_checks.setdefault(c, []).append(a["id"])

        integrity, bound, int_sources, followed = self._integrity(action, ap.risk, roles, lat)
        # action-scoped approvals clear proven paths only, never an incomplete search
        if CheckName.INTEGRITY.value in approved_checks and integrity.raw_violation \
                and not integrity.search.indeterminate:
            integrity.violated = False
            integrity.cleared_by_action_approval = approved_checks[CheckName.INTEGRITY.value]
            for pth in integrity.paths:
                if pth.status == "violating":
                    pth.status = "cleared"
                    pth.cleared_by = list(integrity.cleared_by_action_approval)

        confidentiality, secret, conf_sources = self._confidentiality(
            action, roles, sink_cls.external, lat)
        if CheckName.CONFIDENTIALITY.value in approved_checks and confidentiality.raw_violation \
                and not confidentiality.search.indeterminate:
            confidentiality.violated = False
            confidentiality.cleared_by_action_approval = \
                approved_checks[CheckName.CONFIDENTIALITY.value]
            for pth in confidentiality.paths:
                if pth.status == "violating":
                    pth.status = "cleared"
                    pth.cleared_by = list(confidentiality.cleared_by_action_approval)

        # ---- secret-egress endorsement: a human pre-approved secret egress to exactly this
        # destination value, and that value reaches the destination on a followed path
        if confidentiality.violated and not integrity.raw_violation and bound is True \
                and pol.egress_endorsements:
            t0 = time.perf_counter()
            egress = self._egress_endorsement(action, roles)
            lat["egress_endorsement"] = _ms(t0)
            if egress:
                approvals_ids, path = egress
                confidentiality.violated = False
                confidentiality.cleared_by_endorsement = approvals_ids
                confidentiality.detail += (
                    "; secret egress to this exact destination was pre-approved by human "
                    f"endorsement {', '.join(approvals_ids)} of {path[-1]} "
                    f"(path {' -> '.join(path)})")

        # ---- lethal trifecta: ignores action-scoped approvals on purpose
        # (raw_violation / secret are True for INDETERMINATE searches: a trifecta that
        # cannot be ruled out is treated as one)
        indeterminate = [c.name for c in (integrity, confidentiality)
                         if c.search is not None and c.search.indeterminate]
        trifecta_hit = integrity.raw_violation and secret and sink_cls.external
        trifecta = CheckResult(
            name=CheckName.LETHAL_TRIFECTA, violated=trifecta_hit, raw_violation=trifecta_hit,
            detail=(("cannot be ruled out: provenance search incomplete for "
                     + ", ".join(c.value for c in indeterminate) + " (fail closed)")
                    if trifecta_hit and indeterminate else
                    "untrusted destination + secret payload + external sink" if trifecta_hit else
                    "not all of: untrusted destination (%s), secret payload (%s), external sink (%s)"
                    % (integrity.raw_violation, secret, sink_cls.external)),
            query="integrity_paths ∧ confidentiality_paths ∧ sink policy",
        )

        # ---- human review: policy says this action type always needs a human
        review_by = approved_checks.get(CheckName.HUMAN_REVIEW.value, [])
        review = CheckResult(
            name=CheckName.HUMAN_REVIEW, evaluated=ap.human_review,
            violated=ap.human_review and not review_by, raw_violation=ap.human_review,
            cleared_by_action_approval=list(review_by) if ap.human_review else [],
            detail=(("approved by a human (" + ", ".join(review_by) + ")" if review_by else
                     f"policy requires explicit human approval for every "
                     f"{action.action_type}") if ap.human_review else
                    "policy does not require human review for this action type"),
            query="policy")

        if trifecta_hit:
            verdict = Verdict.BLOCK
            triggered = [CheckName.INTEGRITY, CheckName.CONFIDENTIALITY, CheckName.LETHAL_TRIFECTA]
        elif integrity.violated or confidentiality.violated or review.violated:
            verdict = Verdict.REQUIRE_HUMAN_APPROVAL
            triggered = [c.name for c in (integrity, confidentiality, review) if c.violated]
        else:
            verdict = Verdict.ALLOW
            triggered = []

        # ---- precedent: escalate when a human already rejected secrets to this Sink
        precedent = CheckResult(name=CheckName.PRECEDENT, evaluated=False,
                                detail="only evaluated for a secret payload that would "
                                       "otherwise need approval", query="precedent")
        if verdict == Verdict.REQUIRE_HUMAN_APPROVAL and confidentiality.violated \
                and not confidentiality.search.indeterminate and action.sink is not None \
                and pol.precedent_escalation:
            t0 = time.perf_counter()
            precedent = self._precedent(action, roles)
            lat["precedent_query"] = _ms(t0)
            if precedent.violated:
                verdict = Verdict.BLOCK
                triggered = triggered + [CheckName.PRECEDENT]

        sink_info = self._sink_info(action.sink, sink_cls, bound)
        approval = self._approval_option(verdict, integrity, confidentiality, bound, review)
        sources = self._merge_sources(int_sources + conf_sources)
        explanation = self._explain(action, verdict, integrity, confidentiality, secret,
                                    sink_info, review)
        if precedent.violated:
            p0 = precedent.precedents[0]
            approval = ApprovalOption(
                available=False,
                reason=(f"escalated by precedent: a human rejected secret data to this sink "
                        f"before ({p0.approval_id} REJECTS {p0.rejected_action_id}); the agent "
                        "must propose a different destination"))
            explanation = (f"{action.action_type} by agent '{action.agent}' to "
                           f"{sink_info.destination}. BLOCKED — precedent: the payload is secret "
                           f"and {p0.approver} already rejected secret data to this exact sink "
                           f"({p0.rejected_action_type} {p0.rejected_action_id}, "
                           f"{p0.rejected_at}). Graph evidence: {p0.relationship}. "
                           "Without the precedent this would need human approval: "
                           + confidentiality.detail + ".")
        # ---- explanation only (after the verdict): every untrusted root + independence
        contamination = None
        if pol.contamination_analysis and integrity.raw_violation and integrity.search \
                and integrity.search.path_found:
            t0 = time.perf_counter()
            contamination = self._contamination(action, roles, ap.risk)
            lat["contamination"] = _ms(t0)
            if contamination is not None:
                sources = self._merge_sources(sources + [
                    SourceInfo(id=r.source_id, kind=r.source_kind or "?", trust="untrusted",
                               reached_from=[r.path.arg_datum_id]) for r in contamination.roots])
                explanation += " " + contamination.detail
        decision_id = new_id("dec")
        certificate, no_cert = None, None
        if verdict == Verdict.ALLOW:
            t0 = time.perf_counter()
            certificate, no_cert = self._certificate(
                action, decision_id, roles, integrity, confidentiality, secret, sink_cls.external,
                followed, version_start)
            lat["certificate"] = _ms(t0)
        lat["total"] = _ms(t_total)
        if certificate is not None:
            certificate.guard_latency_ms = lat["total"]
            certificate.certificate_latency_ms = lat["certificate"]
        decision = GuardDecision(
            id=decision_id, action_id=action.id, action_type=action.action_type,
            agent=action.agent, action_status=action.status.value, decision=verdict,
            triggered_checks=triggered, explanation=explanation,
            checks={c.name.value: c for c in (integrity, confidentiality, trifecta, review,
                                              precedent)},
            paths=integrity.paths + confidentiality.paths, sources=sources, sink=sink_info,
            approval=approval, latency_ms=lat, policy=f"{pol.name}@{pol.version}",
            evaluated_at=utcnow_iso(), search_complete=not indeterminate,
            indeterminate_checks=indeterminate, certificate=certificate,
            certificate_unavailable=no_cert, contamination=contamination)
        if indeterminate and verdict == Verdict.ALLOW:  # invariant; never expected
            raise RuntimeError("an incomplete provenance search must never yield ALLOW")
        return self._finish(decision)

    # ------------------------------------------------- complete provenance search
    def _limits(self) -> Dict[str, Any]:
        pol = self.policy
        return {"max_depth": pol.search_max_depth, "max_nodes": pol.search_max_nodes,
                "timeout_ms": pol.search_timeout_ms}

    def _evidence_rows(self, query: str, params: Dict[str, Any], lat: Dict[str, float],
                       key: str) -> Tuple[List[list], Optional[str]]:
        """Bounded path enumeration for evidence. A failure here only loses evidence; the
        verdict comes from the complete search."""
        t0 = time.perf_counter()
        try:
            return self.repo.graph.ro_query(query, params,
                                            timeout=self.policy.evidence_timeout_ms).result_set, None
        except Exception as exc:  # noqa: BLE001
            return [], f"{type(exc).__name__}: {exc}"
        finally:
            lat[key] = _ms(t0)

    def _witness_evidence(self, check: CheckName, action: ActionRecord, search: ProvenanceSearch,
                          status: str) -> Tuple[PathEvidence, Optional[SourceInfo]]:
        """PathEvidence for a witness path found by the complete search (e.g. deeper than
        the evidence queries' max_depth)."""
        ids = search.witness_node_ids
        rows = self.repo.graph.ro_query("MATCH (n) WHERE n.id IN $ids RETURN n",
                                        {"ids": ids}).result_set
        by_id = {r[0].properties["id"]: r[0] for r in rows}
        pnodes = [_path_node(by_id[i]) for i in ids]
        ops = list(search.witness_ops)
        role = next((a.role for a in action.args if a.datum_id == ids[0]), "?")
        length = sum(1 for o in ops if o != "FROM")
        src = pnodes[-1] if "Source" in pnodes[-1].labels else None
        ev = PathEvidence(
            check=check, arg_role=role, arg_datum_id=ids[0], nodes=pnodes, ops=ops,
            length=length, status=status,
            sessions=sorted({n.session_id for n in pnodes if n.session_id}),
            agents=sorted({n.agent for n in pnodes if n.agent}),
            text=_render(action.id, role, pnodes, ops))
        info = (SourceInfo(id=src.id, kind=src.kind or "?", trust=src.trust or "?",
                           reached_from=[ids[0]]) if src else None)
        return ev, info

    def _contamination(self, action: ActionRecord, roles: List[str], risk: RiskTier
                       ) -> Optional[ContaminationReport]:
        """Distinct untrusted roots, one route each, route independence. Never affects the
        verdict; on any failure the decision simply has no report."""
        pol = self.policy
        starts = [a.datum_id for a in action.args if a.role in roles]
        try:
            raw = C.analyse(self.repo.graph, starts, risk_rank=_RISK_RANK[RiskTier(risk).value],
                            max_nodes=pol.search_max_nodes,
                            timeout_ms=pol.contamination_timeout_ms,
                            max_checks=pol.contamination_max_checks)
        except Exception:  # noqa: BLE001 - explanation only
            return None
        if raw.root_count == 0:
            return None
        ids = {i for r in raw.roots + raw.extra_routes for i in r.ids}
        by_id = {r[0].properties["id"]: r[0] for r in self.repo.graph.ro_query(
            "MATCH (n) WHERE n.id IN $ids RETURN n", {"ids": sorted(ids)}).result_set}

        def evidence(r: C.RawRoute) -> PathEvidence:
            pnodes = [_path_node(by_id[i]) for i in r.ids]
            role = next((a.role for a in action.args if a.datum_id == r.ids[0]), "?")
            return PathEvidence(
                check=CheckName.INTEGRITY, arg_role=role, arg_datum_id=r.ids[0], nodes=pnodes,
                ops=list(r.ops), length=len(r.ops) - 1, status="violating",
                sessions=sorted({n.session_id for n in pnodes if n.session_id}),
                agents=sorted({n.agent for n in pnodes if n.agent}),
                text=_render(action.id, role, pnodes, r.ops))

        roots = []
        for r in raw.roots:
            ev = evidence(r)
            src = ev.nodes[-1]
            roots.append(RootRoute(source_id=r.source_id, source_kind=src.kind,
                                   source_label=src.preview, entry_datum_id=r.entry_id,
                                   hops=ev.length, path=ev))
        n = raw.root_count
        names = ", ".join(r.source_id for r in roots) + (", …" if n > len(roots) else "")
        count = (f"{n}" if raw.roots_complete else f"at least {n} (root search incomplete: "
                 f"{raw.roots_search.summary() if raw.roots_search else '?'})")
        detail = f"Untrusted roots detected: {count} ({names})."
        if n > 1:
            detail += (f" {'All' if n > 2 else 'Both'} influence the destination of "
                       f"{action.id}.")
        if raw.independence == "independent":
            detail += (f" Contamination routes: independent — {raw.independent_routes} routes "
                       "sharing no Datum besides the argument "
                       + ("were found (verified)." if raw.method == "disjoint_routes" else
                          "exist: no single Datum lies on every route (verified by complete "
                          "searches)."))
        elif raw.independence == "converging":
            sd = by_id.get(raw.shared_datum_id)
            kind = (sd.properties.get("kind") or "datum") if sd is not None else "datum"
            detail += (" Contamination routes: not independent — every route passes through "
                       f"{kind} {raw.shared_datum_id} (verified: removing it leaves no "
                       "untrusted route).")
        elif raw.independence == "direct":
            detail += " The argument itself is untrusted content."
        else:
            detail += " Route independence: not verified (search budget reached)."
        return ContaminationReport(
            root_count=n, roots_complete=raw.roots_complete, roots=roots,
            independence=raw.independence, independent_routes=raw.independent_routes,
            method=raw.method, shared_datum_id=raw.shared_datum_id,
            extra_routes=[evidence(r) for r in raw.extra_routes], detail=detail,
            checks_run=raw.checks_run, latency_ms=raw.latency_ms)

    # ------------------------------------------------------- egress / precedent
    def _egress_endorsement(self, action: ActionRecord, roles: List[str]
                            ) -> Optional[Tuple[List[str], List[str]]]:
        """(approval ids, path) if a Guard-followed ancestor of the destination argument
        holds exactly the sink's destination value and a human endorsed it with
        ``egress=true``. Incomplete search → None (nothing is cleared: fail closed)."""
        if action.sink is None or not action.sink.destination:
            return None
        dest = action.sink.destination
        res = T.search(self.repo.graph, [a.datum_id for a in action.args if a.role in roles],
                       T.SearchSpec(hit=Q.EGRESS_HIT, edge_ok=T.FOLLOW_EDGE,
                                    params={"fps": [fingerprint(dest), fingerprint(dest.strip())]}),
                       **self._limits())
        if not res.path_found:
            return None
        hit = res.witness_node_ids[-1]
        ids = [r[0] for r in self.repo.graph.ro_query(
            "MATCH (ap:Approval)-[e:ENDORSES {egress: true}]->(:Datum {id: $id}) "
            "WHERE coalesce(ap.approver_kind, 'human') = 'human' RETURN ap.id ORDER BY ap.id",
            {"id": hit}).result_set]
        return (ids, res.witness_node_ids) if ids else None

    def _precedent(self, action: ActionRecord, roles: List[str]) -> CheckResult:
        rows = self.repo.graph.ro_query(Q.PRECEDENT, {"aid": action.id, "roles": roles},
                                        timeout=self.policy.search_timeout_ms).result_set
        precs = []
        for prev, ptype, apid, who, why, at, kid, kdest, pds in rows:
            rel = (f"(:Approval {{id:'{apid}', verdict:'rejected'}})-[:REJECTS]->"
                   f"(:Action {{id:'{prev}'}})-[:TO]->(:Sink {{id:'{kid}'}})<-[:TO]-"
                   f"(:Action {{id:'{action.id}'}}); (:Action {{id:'{prev}'}})-[:ARG]->"
                   f"(:Datum {{id:'{pds[0]}', sensitivity:'secret'}})")
            precs.append(Precedent(rejected_action_id=prev, rejected_action_type=ptype,
                                   approval_id=apid, approver=who, reason=why, rejected_at=at,
                                   sink_id=kid, sink_destination=kdest,
                                   secret_payload_datum_ids=sorted(pds), relationship=rel))
        hit = bool(precs)
        return CheckResult(
            name=CheckName.PRECEDENT, evaluated=True, violated=hit, raw_violation=hit,
            precedents=precs, query="precedent (same Sink + secret payload + human REJECTS)",
            detail=(f"{precs[0].approver} rejected secret data to this sink before: "
                    f"{precs[0].relationship}" if hit else
                    "no human rejection of a secret-bearing action to this sink"))

    # ------------------------------------------------- completeness certificate
    def _certificate(self, action: ActionRecord, decision_id: str, roles: List[str],
                     integrity: CheckResult, confidentiality: CheckResult, secret: bool,
                     external: bool, followed: Dict[str, int], version_start: GraphVersion
                     ) -> Tuple[Optional[ProvenanceCertificate], Optional[str]]:
        """Build the Provenance Completeness Certificate for an ALLOW, or say why not.

        Builds on the verdict's own search (it must be a complete NO_PATH) and adds one
        traversal of the complete recorded ancestor graph (every DERIVED_FROM edge, context
        edges included) to list every reachable Source with its trust and why the Guard
        did or did not follow it. Never issued when anything is incomplete or unstable.
        """
        s = integrity.search
        if s is None or s.outcome != T.SearchOutcome.NO_PATH or not s.search_complete \
                or s.termination_reason != T.TerminationReason.EXHAUSTED:
            return None, "integrity search was not a complete NO_PATH"
        if integrity.raw_violation:
            return None, ("allowed by an explicit human approval of a violating/unbound "
                          "destination: there is no negative claim to certify")
        if not version_start.quiescent:
            return None, "a graph write was in progress when the check started"
        dest_ids = [a.datum_id for a in action.args if a.role in roles]
        if not dest_ids:
            return None, "the action has no destination argument: nothing to certify"

        anc = T.ancestor_graph(self.repo.graph, dest_ids, **self._limits())
        if not anc.complete:
            return None, ("certificate traversal of the complete ancestor graph did not "
                          f"finish ({anc.search.summary()})")

        # nodes reachable WITHOUT context edges (no pruning): separates "context_only" from
        # "cleared by endorsed/typed data"
        no_ctx, stack = set(dest_ids) & set(anc.depth), [d for d in dest_ids if d in anc.depth]
        adj: Dict[str, List[str]] = {}
        for src, dst, _op, attr in anc.edges:
            if attr != "context":
                adj.setdefault(src, []).append(dst)
        while stack:
            for nxt in adj.get(stack.pop(), []):
                if nxt not in no_ctx:
                    no_ctx.add(nxt)
                    stack.append(nxt)

        by_source: Dict[str, RootSource] = {}
        for did, src in anc.sources.items():
            r = by_source.get(src["id"])
            if r is None:
                r = by_source[src["id"]] = RootSource(id=src["id"], kind=src.get("kind"),
                                                      trust=src.get("trust"),
                                                      min_depth=anc.depth[did], status="")
            r.datum_ids.append(did)
            r.min_depth = min(r.min_depth, anc.depth[did])
        for r in by_source.values():
            r.datum_ids.sort()
            if any(d in followed for d in r.datum_ids):
                r.status = "followed"
                r.note = "on a path the Guard follows"
            elif any(d in no_ctx for d in r.datum_ids):
                r.status = "cleared"
                r.note = "every Guard-followed path passes through human-endorsed or typed data"
            else:
                r.status = "context_only"
                r.note = ("reached only through context edges: a trusted Datum supplied the "
                          "value verbatim (exact-value attribution)")
            if r.status == "followed" and r.trust == "untrusted":  # contradicts NO_PATH
                return None, f"inconsistent evidence: untrusted {r.id} on a followed path"
        roots = sorted(by_source.values(), key=lambda r: (r.trust != "untrusted", r.min_depth, r.id))

        version_end = self.repo.graph_version()
        if version_end != version_start:
            return None, (f"the graph changed during the check ({version_start.label} → "
                          f"{version_end.label}); re-check to certify")

        ctx_edges = sum(1 for e in anc.edges if e[3] == "context")
        digest = hashlib.sha256(json.dumps({
            "start": sorted(dest_ids),
            "nodes": sorted([d, anc.node_flags.get(d, {})] for d in anc.depth),
            "edges": sorted(list(e) for e in anc.edges),
            "from": sorted([d, src["id"], src.get("trust")] for d, src in anc.sources.items()),
        }, sort_keys=True).encode()).hexdigest()
        if secret and confidentiality.cleared_by_endorsement:
            payload = ("payload derives from secret data; secret egress to this exact "
                       "destination pre-approved by human endorsement "
                       + ", ".join(confidentiality.cleared_by_endorsement))
        elif secret:
            payload = ("payload derives from secret data; "
                       + ("allowed by human approval" if external else "the sink is internal"))
        else:
            payload = ("payload has no secret provenance (complete search, "
                       f"{confidentiality.search.nodes_visited if confidentiality.search else 0}"
                       " node(s))")
        label = version_start.label

        # provenance coverage of every model-produced Datum in the examined ancestry
        reduced = sorted(
            (d for d, f in anc.node_flags.items()
             if f.get("kind") in MODEL_OUTPUT_KINDS
             and f.get("coverage") != ProvenanceCoverage.FULL_CONTEXT.value),
            key=lambda d: (anc.depth.get(d, 0), d))
        coverage = (ProvenanceCoverage.REDUCED if reduced else ProvenanceCoverage.FULL_CONTEXT)
        strength = "DOWNGRADED" if reduced else "STRONG"
        base = ("No untrusted influence was found relative to the recorded provenance graph "
                f"(graph version {label}) and current Source trust labels.")
        if reduced:
            claim = (base + f" DOWNGRADED: {len(reduced)} model output(s) in this ancestry "
                     "were recorded with REDUCED provenance (narrower than their context "
                     "window, or coverage not recorded), so this is NOT an exhaustive account "
                     "of recorded influence: an untrusted item those outputs saw but did not "
                     "link would not appear here.")
        else:
            claim = (base + " Every model output in the ancestry recorded edges to its whole "
                     "context window (FULL_CONTEXT) and the traversal was complete.")
        claim += (" Paths the Guard does not follow are listed with the reason (context-only "
                  "edges, human-endorsed or typed data). Trust labels are policy inputs, not "
                  "findings. Influence the runtime never recorded (e.g. implicit flows) is "
                  "outside this claim; it does not say the action is safe.")
        id_inputs = {
            "action": action.id, "destination": sorted(dest_ids),
            "graph": version_start.graph, "graph_version": version_start.finished,
            "ancestry_digest": "sha256:" + digest,
            "roots": [[r.id, r.trust, r.status] for r in roots],
            "coverage": coverage.value, "reduced": reduced,
            "policy": f"{self.policy.name}@{self.policy.version}", "payload": payload,
        }
        cert_id = "pcc_" + hashlib.sha256(json.dumps(id_inputs, sort_keys=True)
                                          .encode()).hexdigest()[:16]
        return ProvenanceCertificate(
            id=new_id("cert"), action_id=action.id, decision_id=decision_id,
            issued_at=utcnow_iso(),
            claim=claim,
            provenance_coverage=coverage.value, strength=strength,
            reduced_provenance_count=len(reduced),
            reduced_provenance=[{"datum_id": d, "kind": anc.node_flags[d].get("kind"),
                                 "coverage": anc.node_flags[d].get("coverage") or "not recorded"}
                                for d in reduced[:20]],
            certificate_id=cert_id, certificate_id_inputs=sorted(id_inputs),
            scope="destination argument(s): " + ", ".join(sorted(dest_ids)),
            traversal_complete=True, frontier_exhausted=True,
            termination_reason=anc.search.termination_reason.value,
            root_sources_checked=len(roots), root_sources=roots,
            untrusted_roots_not_followed=sum(r.trust == "untrusted" for r in roots),
            max_depth_reached=max(anc.depth.values()),
            nodes_examined=len(anc.depth),
            relationships_examined=len(anc.edges) + len(anc.sources),
            derived_from_edges_examined=len(anc.edges), context_edges_examined=ctx_edges,
            context_provenance_included=True, guard_followed_nodes=len(followed),
            graph=version_start.graph, graph_version=version_start.finished,
            graph_version_label=label, ancestry_digest="sha256:" + digest, payload=payload,
            integrity_search=s.model_copy(update={"witness_node_ids": [], "witness_ops": []}),
            ancestor_search=anc.search, limits=self._limits()), None

    # ------------------------------------------------------------ integrity
    def _integrity(self, action: ActionRecord, action_risk: RiskTier, roles: List[str],
                   lat: Dict[str, float]
                   ) -> Tuple[CheckResult, Optional[bool], List[SourceInfo], Dict[str, int]]:
        pol = self.policy
        rows, evidence_error = self._evidence_rows(
            Q.integrity_paths(pol.max_depth),
            {"aid": action.id, "roles": roles, "limit": pol.path_limit}, lat, "integrity_query")

        endorsed_all: Set[str] = {i for r in rows for i in r[5]}
        endorsements = self.repo.endorsements_of(sorted(endorsed_all)) if endorsed_all else {}

        paths: List[PathEvidence] = []
        sources: List[SourceInfo] = []
        risk_rank = _RISK_RANK[RiskTier(action_risk).value]
        for role, arg_id, nodes, rels, src, endorsed_ids, typed_ids, length in rows:
            pnodes = [_path_node(n) for n in nodes] + [_path_node(src)]
            ops = [r.properties.get("op", r.relation) for r in rels] + ["FROM"]
            if endorsed_ids:
                status = "cleared"
                cleared_by = sorted({a["id"] for d in endorsed_ids for a in endorsements.get(d, [])})
            else:
                cleared_by = []
                typed_ok = [n for n in nodes if n.properties.get("quarantined")
                            and _RISK_RANK.get(n.properties.get("max_risk", "low"), 0) >= risk_rank]
                status = "limited" if typed_ok else "violating"
            paths.append(PathEvidence(
                check=CheckName.INTEGRITY, arg_role=role, arg_datum_id=arg_id, nodes=pnodes,
                ops=ops, length=length, status=status, cleared_by=cleared_by,
                endorsed_datum_ids=list(endorsed_ids), typed_datum_ids=list(typed_ids),
                sessions=sorted({n.session_id for n in pnodes if n.session_id}),
                agents=sorted({n.agent for n in pnodes if n.agent}),
                text=_render(action.id, role, pnodes, ops)))
            sources.append(SourceInfo(id=src.properties["id"], kind=src.properties["kind"],
                                      trust=src.properties["trust"], reached_from=[arg_id]))

        # ---- destination binding
        t0 = time.perf_counter()
        k, fps, dest_ids = self.repo.graph.ro_query(
            Q.DESTINATION_BINDING, {"aid": action.id, "roles": roles}).result_set[0]
        lat["binding_query"] = _ms(t0)
        bound: Optional[bool] = None
        if k is not None:
            dest = k.properties.get("destination", "")
            bound = bool({fingerprint(dest), fingerprint(dest.strip())} & set(fps))

        violating = [p for p in paths if p.status == "violating"]

        # ---- verdict: complete reachability (the evidence query above is depth-bounded)
        t0 = time.perf_counter()
        followed: Dict[str, int] = {}  # nodes on Guard-followed paths (for the certificate)
        if violating:
            w = violating[0]
            search = T.witness_from_bounded([n.id for n in w.nodes], w.ops,
                                            lat["integrity_query"], pol.max_depth)
        else:
            search = T.untrusted_origin(
                self.repo.graph, [a.datum_id for a in action.args if a.role in roles],
                risk_rank=risk_rank, collect=followed, **self._limits())
            if search.path_found:  # beyond the evidence depth: surface the witness path
                ev, info = self._witness_evidence(CheckName.INTEGRITY, action, search, "violating")
                paths.append(ev)
                violating = [ev]
                if info:
                    sources.append(info)
        lat["integrity_search"] = _ms(t0)

        raw = bool(violating) or search.indeterminate or bound is False
        details = []
        if search.indeterminate:
            details.append("provenance search incomplete (" + search.summary() + "): an "
                           "untrusted origin of the destination cannot be ruled out (fail closed)")
        if evidence_error:
            details.append(f"path evidence query failed ({evidence_error})")
        if violating:
            srcs = sorted({p.nodes[-1].id for p in violating})
            details.append(f"{len(violating)} uncleared path(s) from the destination to "
                           f"untrusted source(s) {', '.join(srcs)}")
        if bound is False:
            details.append("the sink's destination does not match any recorded destination "
                           "argument (unattributed destination, fail closed)")
        cleared = [p for p in paths if p.status == "cleared"]
        limited = [p for p in paths if p.status == "limited"]
        if not raw:
            details.append("destination has no uncleared path to an untrusted source "
                           f"(complete search: {search.nodes_visited} node(s), "
                           f"depth {search.depth_explored})"
                           + (f" ({len(cleared)} path(s) cleared by endorsement)" if cleared else "")
                           + (f" ({len(limited)} path(s) via typed values, allowed for "
                              f"low-risk actions)" if limited else ""))
        return (CheckResult(name=CheckName.INTEGRITY, violated=raw, raw_violation=raw,
                            detail="; ".join(details), paths=paths,
                            latency_ms=round(lat["integrity_query"] + lat["binding_query"]
                                             + lat["integrity_search"], 3),
                            query=Q.QUERY_NAMES["integrity"] + " + " + Q.QUERY_NAMES["binding"]
                            + " + untrusted_origin_search", search=search),
                bound, sources, followed)

    # ------------------------------------------------------- confidentiality
    def _confidentiality(self, action: ActionRecord, roles: List[str], external: bool,
                         lat: Dict[str, float]) -> Tuple[CheckResult, bool, List[SourceInfo]]:
        pol = self.policy
        rows, evidence_error = self._evidence_rows(
            Q.confidentiality_paths(pol.max_depth),
            {"aid": action.id, "roles": roles, "limit": pol.path_limit * 2}, lat,
            "confidentiality_query")
        # keep maximal paths only (drop paths that are a prefix of a longer returned path)
        id_lists = [[n.properties["id"] for n in r[2]] for r in rows]
        keep = []
        for i, ids in enumerate(id_lists):
            if any(j != i and len(o) > len(ids) and o[:len(ids)] == ids
                   and rows[j][1] == rows[i][1] for j, o in enumerate(id_lists)):
                continue
            keep.append(i)
        status = "violating" if external else "info"
        paths: List[PathEvidence] = []
        sources: List[SourceInfo] = []
        for i in keep:
            role, arg_id, nodes, rels, src, length = rows[i]
            pnodes = [_path_node(n) for n in nodes] + ([_path_node(src)] if src is not None else [])
            ops = [r.properties.get("op", r.relation) for r in rels] + (["FROM"] if src else [])
            paths.append(PathEvidence(
                check=CheckName.CONFIDENTIALITY, arg_role=role, arg_datum_id=arg_id,
                nodes=pnodes, ops=ops, length=length, status=status,
                sessions=sorted({n.session_id for n in pnodes if n.session_id}),
                agents=sorted({n.agent for n in pnodes if n.agent}),
                text=_render(action.id, role, pnodes, ops)))
            if src is not None:
                sources.append(SourceInfo(id=src.properties["id"], kind=src.properties["kind"],
                                          trust=src.properties["trust"], reached_from=[arg_id]))
        # ---- verdict: complete reachability (the evidence query above is depth-bounded)
        t0 = time.perf_counter()
        if paths:
            w = paths[0]
            search = T.witness_from_bounded([n.id for n in w.nodes], w.ops,
                                            lat["confidentiality_query"], pol.max_depth)
        else:
            search = T.secret_origin(
                self.repo.graph, [a.datum_id for a in action.args if a.role not in roles],
                **self._limits())
            if search.path_found:  # beyond the evidence depth: surface the witness path
                ev, _ = self._witness_evidence(CheckName.CONFIDENTIALITY, action, search, status)
                paths.append(ev)
        lat["confidentiality_search"] = _ms(t0)

        # INDETERMINATE counts as secret: unknown provenance is never assumed clean
        secret = search.path_found or search.indeterminate
        raw = secret and external
        if search.indeterminate:
            detail = ("provenance search incomplete (" + search.summary() + "): the payload "
                      "may derive from secret data (fail closed)"
                      + ("" if external else "; the sink is internal"))
        elif raw:
            origins = sorted({p.nodes[-1].id for p in paths})
            detail = f"payload derives from secret data ({', '.join(origins)}) and the sink is external"
        elif secret:
            detail = "payload derives from secret data but the sink is internal"
        else:
            detail = ("payload does not derive from secret data (complete search: "
                      f"{search.nodes_visited} node(s), depth {search.depth_explored})")
        if evidence_error:
            detail += f"; path evidence query failed ({evidence_error})"
        return (CheckResult(name=CheckName.CONFIDENTIALITY, violated=raw, raw_violation=raw,
                            detail=detail, paths=paths,
                            latency_ms=round(lat["confidentiality_query"]
                                             + lat["confidentiality_search"], 3),
                            query=Q.QUERY_NAMES["confidentiality"] + " + secret_origin_search",
                            search=search),
                secret, sources)

    # --------------------------------------------------------------- pieces
    @staticmethod
    def _sink_info(sink: Optional[SinkRecord], cls, bound: Optional[bool]) -> SinkInfo:
        return SinkInfo(id=sink.id if sink else None, kind=sink.kind if sink else None,
                        destination=sink.destination if sink else None,
                        workspace=sink.workspace if sink else None,
                        declared_external=sink.external if sink else None,
                        external=cls.external, zone=cls.zone, reason=cls.reason, bound=bound)

    @staticmethod
    def _merge_sources(items: Iterable[SourceInfo]) -> List[SourceInfo]:
        out: Dict[str, SourceInfo] = {}
        for s in items:
            if s.id in out:
                out[s.id].reached_from = sorted(set(out[s.id].reached_from) | set(s.reached_from))
            else:
                out[s.id] = s.model_copy()
        return list(out.values())

    @staticmethod
    def _approval_option(verdict: Verdict, integrity: CheckResult,
                         confidentiality: CheckResult, bound: Optional[bool],
                         review: Optional[CheckResult] = None) -> ApprovalOption:
        if verdict == Verdict.BLOCK:
            return ApprovalOption(
                available=False,
                reason="lethal trifecta (untrusted destination + secret payload + external "
                       "sink) cannot be approved; the agent must propose a different action")
        if verdict == Verdict.ALLOW:
            return ApprovalOption(available=False, reason="nothing to approve")
        incomplete = [c.name.value for c in (integrity, confidentiality)
                      if c.search is not None and c.search.indeterminate]
        if incomplete:
            return ApprovalOption(
                available=False,
                reason="provenance search incomplete for " + " and ".join(incomplete)
                       + "; there is nothing concrete to approve. Re-check once the search can "
                       "complete (e.g. after a transient failure, or with higher search limits)")
        endorse: List[str] = []
        checks: List[str] = []
        if integrity.violated:
            endorse = sorted({p.arg_datum_id for p in integrity.paths if p.status == "violating"})
            if bound is False:
                checks.append(CheckName.INTEGRITY.value)
        if confidentiality.violated:
            checks.append(CheckName.CONFIDENTIALITY.value)
        if review is not None and review.violated:
            checks.append(CheckName.HUMAN_REVIEW.value)
        parts = []
        if endorse:
            parts.append("endorse the destination datum(s) " + ", ".join(endorse))
        if checks:
            parts.append("approve " + " and ".join(checks) + " for this action only")
        return ApprovalOption(available=True, reason="a human may " + " and ".join(parts),
                              endorse_datum_ids=endorse, approve_checks=checks)

    @staticmethod
    def _explain(action: ActionRecord, verdict: Verdict, integrity: CheckResult,
                 confidentiality: CheckResult, secret: bool, sink: SinkInfo,
                 review: Optional[CheckResult] = None) -> str:
        where = f"{sink.destination} ({sink.zone}: {sink.reason})" if sink.destination else "no sink"
        head = f"{action.action_type} by agent '{action.agent}' to {where}. "
        if verdict == Verdict.BLOCK:
            worst = next(p for p in integrity.paths if p.status == "violating") \
                if any(p.status == "violating" for p in integrity.paths) else None
            via = ""
            if worst:
                via = (f" Shortest uncleared route (shown as evidence): from {worst.nodes[-1].id}, "
                       f"{worst.length} DERIVED_FROM hop(s) across sessions "
                       f"{', '.join(worst.sessions) or '-'} and agents {', '.join(worst.agents) or '-'}.")
            incomplete = [c.name.value for c in (integrity, confidentiality)
                          if c.search is not None and c.search.indeterminate]
            if incomplete:
                return (head + "BLOCKED — lethal trifecta cannot be ruled out: the provenance "
                        "search did not complete for " + " and ".join(incomplete) + ", and "
                        "an incomplete search is never treated as safe. Integrity: "
                        + integrity.detail + ". Confidentiality: " + confidentiality.detail
                        + ". This action cannot be approved.")
            return (head + "BLOCKED — lethal trifecta: the destination is influenced by "
                    "untrusted data, the payload contains secret data, and the sink is external."
                    + via + " " + confidentiality.detail.capitalize() + ". "
                    "This action cannot be approved.")
        if verdict == Verdict.REQUIRE_HUMAN_APPROVAL:
            reasons = []
            if integrity.violated:
                reasons.append("Integrity: " + integrity.detail)
            if confidentiality.violated:
                reasons.append("Confidentiality: " + confidentiality.detail)
            if review is not None and review.violated:
                reasons.append("Human review: " + review.detail)
            return head + "Human approval required. " + ". ".join(reasons) + "."
        bits = ["Integrity: " + integrity.detail]
        if integrity.cleared_by_action_approval:
            bits.append("integrity approved for this action by "
                        + ", ".join(integrity.cleared_by_action_approval))
        bits.append("Confidentiality: " + confidentiality.detail)
        if confidentiality.cleared_by_action_approval:
            bits.append("confidentiality approved for this action by "
                        + ", ".join(confidentiality.cleared_by_action_approval))
        if review is not None and review.evaluated:
            bits.append("Human review: " + review.detail)
        return head + "Allowed. " + ". ".join(bits) + "."

    def _finish(self, decision: GuardDecision) -> GuardDecision:
        if self.record_decisions:
            self.repo.create_decision({
                "id": decision.id, "action_id": decision.action_id,
                "decision": decision.decision.value,
                "triggered": [c.value for c in decision.triggered_checks],
                "explanation": decision.explanation,
                "sink_external": decision.sink.external,
                "latency_ms": decision.latency_ms.get("total", 0.0),
                "policy": decision.policy, "created_at": decision.evaluated_at,
                "seq": time.time_ns(),
            })
        return decision

    # ============================================================ lifecycle
    def enforce(self, action_id: str) -> GuardDecision:
        """Check and move the action's status: ALLOW→approved, approval→pending_approval,
        BLOCK→blocked. Terminal statuses (blocked, rejected, executed, failed) are sticky."""
        decision = self.check(action_id)
        current = ActionStatus(decision.action_status)
        if current in _OPEN_STATUSES:
            new = {Verdict.ALLOW: ActionStatus.APPROVED,
                   Verdict.REQUIRE_HUMAN_APPROVAL: ActionStatus.PENDING_APPROVAL,
                   Verdict.BLOCK: ActionStatus.BLOCKED}[decision.decision]
            if new != current:
                self.repo.set_action_status(action_id, new)
            decision.action_status = new.value
        return decision

    @staticmethod
    def _require_human(approver: str, approver_kind: str) -> None:
        if approver_kind != "human" or not approver or approver.startswith("system:"):
            raise ApprovalRefused("only a human approver can approve or endorse")

    def approve(self, action_id: str, *, approver: str, reason: Optional[str] = None,
                approver_kind: str = "human") -> GuardDecision:
        """Apply the approval the policy offers for this action, then re-run the Guard.

        Integrity → ENDORSES the destination datum(s) (re-check sees the endorsed node on
        the path). Confidentiality, or an unbound destination → APPROVES the action for
        those checks only. Lethal trifecta → ApprovalRefused.
        """
        self._require_human(approver, approver_kind)
        action = self.repo.get_action(action_id)
        if action.status == ActionStatus.BLOCKED:
            raise ApprovalRefused(f"action {action_id} was blocked as a lethal trifecta; "
                                  "it has no approval option")
        if action.status in _TERMINAL_STATUSES:
            raise ApprovalRefused(f"action {action_id} is {action.status.value}; "
                                  "it cannot be approved")
        decision = self.check(action_id)
        if decision.decision == Verdict.BLOCK:
            self.repo.set_action_status(action_id, ActionStatus.BLOCKED)
            raise ApprovalRefused(decision.approval.reason)
        if decision.decision == Verdict.REQUIRE_HUMAN_APPROVAL and not decision.approval.available:
            raise ApprovalRefused(decision.approval.reason)
        if decision.decision == Verdict.REQUIRE_HUMAN_APPROVAL:
            opt = decision.approval
            self.recorder.record_approval(
                approver=approver, approver_kind=approver_kind, endorses=opt.endorse_datum_ids,
                action_id=action_id, checks=opt.approve_checks or [], reason=reason)
        return self.enforce(action_id)

    def endorse(self, datum_ids: Sequence[str], *, approver: str, reason: Optional[str] = None,
                approver_kind: str = "human", egress: bool = False) -> ApprovalRecord:
        """Data-level endorsement (a human vouches for these Datums).

        Refused for any Datum on the destination provenance of a BLOCKED action, so a
        lethal-trifecta block can never be turned into an approvable action by endorsing
        its inputs after the fact.
        """
        self._require_human(approver, approver_kind)
        ids = list(dict.fromkeys(datum_ids))
        pairs = []
        # complete search per blocked action (no depth bound); unknown counts as "feeds it"
        for aid, dest_ids in self.repo.graph.ro_query(
                Q.BLOCKED_DESTINATIONS,
                {"roles": sorted(self.policy.destination_roles)}).result_set:
            res = T.search(self.repo.graph, dest_ids,
                           T.SearchSpec(hit="m.id IN $endorse_ids", edge_ok=T.FOLLOW_EDGE,
                                        params={"endorse_ids": ids}), **self._limits())
            if res.path_found:
                pairs.append(f"{res.witness_node_ids[-1]} → {aid}")
            elif res.indeterminate:
                raise ApprovalRefused(f"cannot verify that {', '.join(ids)} do not feed blocked "
                                      f"action {aid} (provenance search incomplete: "
                                      f"{res.termination_reason.value}); refusing to endorse")
        if pairs:
            raise ApprovalRefused(f"cannot endorse data feeding blocked action(s): "
                                  f"{', '.join(pairs)}")
        return self.recorder.record_approval(approver=approver, approver_kind=approver_kind,
                                             endorses=ids, reason=reason, egress=egress)

    def reject(self, action_id: str, *, approver: str, reason: Optional[str] = None) -> ActionRecord:
        self._require_human(approver, "human")
        action = self.repo.get_action(action_id)
        if action.status in _TERMINAL_STATUSES:
            return action
        self.recorder.record_rejection(approver=approver, action_id=action_id, reason=reason)
        self.repo.set_action_status(action_id, ActionStatus.REJECTED)
        return self.repo.get_action(action_id)

    def decisions(self, action_id: str) -> List[Dict[str, Any]]:
        return self.repo.decisions_for(action_id)
