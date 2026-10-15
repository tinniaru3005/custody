"""Correctness benchmark: Custody vs baselines on labelled provenance cases.

    python -m bench.run_correctness                      # embedded FalkorDB, 10 variants/family
    python -m bench.run_correctness --variants 20 --seed 7
    python -m bench.run_correctness --host localhost     # a FalkorDB server instead
    ANTHROPIC_API_KEY=... python -m bench.run_correctness --llm-judge   # adds the LLM judge

Writes bench/results/correctness.json and bench/results/correctness.md.
"""
from __future__ import annotations

import argparse
import json
import time
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Optional
from urllib.parse import urlparse

from bench import baselines as B
from bench.cases import CONTEXTS, build_all
from bench.common import SqlMirror, connect, export_graph, fresh, machine_info, ms, summary

RESULTS = Path(__file__).resolve().parent / "results"
TAU = 0.35            # vector threshold, fixed before the first run; the sweep is reported too
TAU_SWEEP = [0.2, 0.3, 0.35, 0.4, 0.5, 0.6]
TOP_K = 5
BOUNDED_TIMEOUT_MS = 2_000      # same budget as the Guard's complete search
CHAIN_SWEEP = [0.2, 0.3, 0.35, 0.4, 0.5, 0.6, 0.7, 0.8]


def confusion(rows: List[dict], method: str) -> Dict[str, object]:
    tp = fp = tn = fn = abstain = 0
    for r in rows:
        p = r["pred"].get(method)
        if p is None:
            abstain += 1
            continue
        if r["label"] == "dangerous":
            tp += p
            fn += not p
        else:
            fp += p
            tn += not p
    pos, neg = tp + fn, tn + fp
    out = {"TP": tp, "FP": fp, "TN": tn, "FN": fn, "abstain": abstain,
           "recall": round(tp / pos, 3) if pos else None,
           "false_positive_rate": round(fp / neg, 3) if neg else None,
           "precision": round(tp / (tp + fp), 3) if tp + fp else None,
           "accuracy": round((tp + tn) / (pos + neg), 3) if pos + neg else None}
    return out


def _verdict_sets(xs: List[object]) -> int:
    return len({json.dumps(x, sort_keys=True) for x in xs})


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--variants", type=int, default=10, help="cases per family")
    ap.add_argument("--seed", type=int, default=1234)
    ap.add_argument("--families", choices=["all", "v1"], default="all",
                    help="v1 = the original 15 families (150 cases at 10 variants)")
    ap.add_argument("--repeats", type=int, default=5,
                    help="identical re-runs of every deterministic method (determinism)")
    ap.add_argument("--host", help="FalkorDB server host (default: embedded falkordblite)")
    ap.add_argument("--port", type=int, default=6379)
    ap.add_argument("--llm-judge", action="store_true", help="also run the LLM judge")
    ap.add_argument("--llm-runs", type=int, default=10, help="identical LLM runs per case")
    ap.add_argument("--llm-cases", type=int, default=0,
                    help="judge only the first N cases of each family (0 = all)")
    ap.add_argument("--llm-price-in", type=float, default=None, help="USD per 1M input tokens")
    ap.add_argument("--llm-price-out", type=float, default=None, help="USD per 1M output tokens")
    ap.add_argument("--sbert", action="store_true", help="also run a sentence-transformers index")
    ap.add_argument("--out", default=str(RESULTS))
    a = ap.parse_args(argv)

    from bench.cases import FAMILIES, FAMILIES_V1, SECRET_INVENTORY, category
    from custody.graph import traversal as T
    from custody.guard import queries as Q

    db, backend = connect(a.host, a.port)
    _, rec, guard, rt = fresh(db, "bench-correctness")
    t0 = time.perf_counter()
    cases = build_all(rt, a.variants, a.seed,
                      families=FAMILIES_V1 if a.families == "v1" else FAMILIES)
    build_ms = ms(t0)
    ex = export_graph(rec)
    untrusted = [d for d in ex.docs.values() if d.source_trust == "untrusted"]
    t0 = time.perf_counter()
    sql = SqlMirror(ex)
    sql_build = ms(t0)
    # The retrieval corpus is a document/memory store: external documents, user messages,
    # shared memories and inter-agent messages (not every intermediate model output, and
    # not the action's own argument values). Every chunk carries its source's trust label.
    corpus = {k: v for k, v in ex.docs.items() if v.kind in B.CORPUS_KINDS}
    vec = B.VectorIndex(corpus, "tfidf")
    lsa = B.VectorIndex(corpus, "lsa")
    sbert = None
    skipped: Dict[str, str] = {}
    if a.sbert:
        why = B.sbert_available()
        if why is None:
            try:
                sbert = B.VectorIndex(corpus, "sbert")
            except Exception as exc:  # noqa: BLE001 - e.g. model download blocked
                why = f"{type(exc).__name__}: {exc}"
        if why:
            skipped["vector_sbert"] = why
    else:
        skipped["vector_sbert"] = "not requested (--sbert); model download blocked here"
    judge = None
    if a.llm_judge:
        why = B.llm_judge_unavailable()
        if why is None:
            judge = B.LLMJudge()
        else:
            skipped["llm_judge"] = why
    else:
        skipped["llm_judge"] = "not requested (--llm-judge; needs ANTHROPIC_API_KEY)"
    bounded_q = Q.integrity_paths(25)
    payload_arg = {aid: d for aid, role, d in ex.args if role == "payload"}

    lat: Dict[str, List[float]] = defaultdict(list)
    rows = []
    per_family_seen: Dict[str, int] = defaultdict(int)
    for c in cases:
        pred: Dict[str, Optional[bool]] = {}
        info: Dict[str, object] = {"category": category(c.family), "params": c.params}
        arg_ids = {d for aid, _, d in ex.args if aid == c.action_id}
        ctx = [ex.docs[i] for i in CONTEXTS[c.action_id] if i in ex.docs and i not in arg_ids]
        reps: Dict[str, List[object]] = defaultdict(list)

        for rep in range(max(1, a.repeats)):
            t = time.perf_counter()
            d = guard.check(c.action_id)
            if rep == 0:
                lat["custody"].append(ms(t))
                info["custody_ms"] = round(ms(t), 3)
            reps["custody"].append(d.decision.value)
        s = d.checks["integrity"].search
        pred["custody"] = bool(d.checks["integrity"].raw_violation)
        info["custody_verdict"] = d.decision.value
        info["custody_outcome"] = s.outcome.value
        info["custody_proof_of_absence"] = s.proves_no_path
        info["custody_search_ms"] = s.latency_ms
        info["custody_nodes_visited"] = s.nodes_visited
        ev = next((p for p in d.paths if p.check.value == "integrity"
                   and p.status == "violating"), None)
        info["custody_witness_hops"] = ev.length if ev else None
        info["custody_certificate"] = d.certificate is not None
        # every distinct untrusted root (complete BFS over the destination's followed
        # ancestry) and whether the routes to them are independent (verified or not)
        cont = d.contamination
        info["custody_untrusted_roots"] = sorted(r.source_id for r in cont.roots) if cont else []
        info["custody_root_count"] = cont.root_count if cont else 0
        info["custody_roots_complete"] = cont.roots_complete if cont else None
        info["custody_routes"] = (f"{cont.independence}"
                                  + (f" via {cont.shared_datum_id}" if cont.shared_datum_id else "")
                                  + (f" ({cont.independent_routes} disjoint)"
                                     if cont.independence == "independent" else "")) if cont else None

        for rep in range(max(1, a.repeats)):
            t = time.perf_counter()
            found, visited = sql.untrusted_destination(c.action_id)
            if rep == 0:
                lat["sql_cte"].append(ms(t))
            reps["sql_cte"].append(found)
        pred["sql_cte"] = found
        info["sql_cte_visited"] = visited

        # the depth-bounded variable-length Cypher pattern (*0..25) Custody used before
        # (path enumeration: a server-side timeout is an answer of "unknown", scored as an
        # escalation, i.e. fail-closed, and counted separately)
        t = time.perf_counter()
        try:
            brows = guard.repo.graph.ro_query(
                bounded_q, {"aid": c.action_id, "roles": ["destination"], "limit": 50},
                timeout=BOUNDED_TIMEOUT_MS).result_set
            pred["cypher_bounded_25"] = any(not r[5] and not r[6] for r in brows)
            info["cypher_bounded_25_timeout"] = False
        except Exception:  # noqa: BLE001 - timeout
            pred["cypher_bounded_25"] = True
            info["cypher_bounded_25_timeout"] = True
        lat["cypher_bounded_25"].append(ms(t))

        t = time.perf_counter()
        pred["keyword_scan"] = B.keyword_scan(ctx)
        lat["keyword_scan"].append(ms(t))
        t = time.perf_counter()
        pred["string_exact"] = B.string_exact(c.destination, untrusted)
        lat["string_exact"].append(ms(t))
        t = time.perf_counter()
        pred["string_attributed"] = B.string_attributed(c.destination, untrusted, ctx)
        lat["string_attributed"].append(ms(t))
        t = time.perf_counter()
        pred["string_host"] = B.string_host(c.destination, untrusted)
        lat["string_host"].append(ms(t))
        reps["string_exact"] = [B.string_exact(c.destination, untrusted)
                                for _ in range(max(1, a.repeats))]

        # vector retrieval: keep the top-10 (similarity, trust) for both query forms and
        # both models; every (tau, k) operating point is evaluated from these afterwards
        host = urlparse(c.destination).hostname or c.destination
        tops = {}
        for name, idx in (("tfidf", vec), ("lsa", lsa)):
            for qname, q in (("url", c.destination), ("host", host)):
                t = time.perf_counter()
                tops[f"{name}/{qname}"] = [(round(sim, 4), tr) for sim, tr in idx.top(q, 10)]
                if qname == "url":
                    lat[f"vector_{name}"].append(ms(t))
        info["vector_tops"] = tops
        info["vector_top"] = tops["tfidf/url"][:TOP_K]
        hits = tops["tfidf/url"][:TOP_K]
        pred["vector_tfidf"] = any(sim >= TAU and tr == "untrusted" for sim, tr in hits)
        for tau in TAU_SWEEP:
            pred[f"vector_tfidf@{tau}"] = any(sim >= tau and tr == "untrusted" for sim, tr in hits)
        reps["vector_tfidf"] = [vec.flag(c.destination, TAU, TOP_K)
                                for _ in range(max(1, a.repeats))]
        t = time.perf_counter()
        pred["vector_chain"] = vec.chain_flag(c.destination, TAU, TOP_K)
        lat["vector_chain"].append(ms(t))
        info["vector_chain_sweep"] = {str(tau): vec.chain_flag(c.destination, tau, TOP_K)
                                      for tau in CHAIN_SWEEP}
        if sbert is not None:
            t = time.perf_counter()
            pred["vector_sbert"] = sbert.flag(c.destination, TAU)
            lat["vector_sbert"].append(ms(t))

        # payload question (families that put a secret in the acting context)
        if c.payload_secret is not None:
            pid = payload_arg[c.action_id]
            t = time.perf_counter()
            ps = T.secret_origin(guard.repo.graph, [pid])
            lat["payload_custody"].append(ms(t))
            info["payload"] = {
                "truth": c.payload_secret, "transform": c.transform,
                "custody": ps.path_found, "custody_complete": ps.search_complete,
                "dlp_exact": B.dlp_exact(c.payload, SECRET_INVENTORY),
                "dlp_decode": B.dlp_decode(c.payload, SECRET_INVENTORY),
                "dlp_pattern": B.dlp_pattern(c.payload)}

        if judge is not None and (not a.llm_cases or per_family_seen[c.family] < a.llm_cases):
            verdicts, usage, l_ms = [], [], []
            for _ in range(max(1, a.llm_runs)):
                t = time.perf_counter()
                v, raw = judge.judge(c.destination, ctx)
                l_ms.append(ms(t))
                verdicts.append(v)
                usage.append(dict(judge.last_usage))
            lat["llm_judge"].extend(l_ms)
            maj = [v for v in verdicts if v is not None]
            pred["llm_judge"] = (sum(maj) * 2 >= len(maj)) if maj else None   # majority
            info["llm"] = {"verdicts": verdicts, "usage": usage, "last_raw": raw}
            reps["llm_judge"] = verdicts
        per_family_seen[c.family] += 1
        info["distinct_verdicts"] = {m: _verdict_sets(v) for m, v in reps.items()}
        rows.append({"case": c.name, "family": c.family, "label": c.label, "note": c.note,
                     "destination": c.destination, "pred": pred, "info": info})

    methods = ["custody", "sql_cte", "cypher_bounded_25", "keyword_scan", "string_exact",
               "string_host", "string_attributed", "vector_tfidf", "vector_chain"] + \
              (["vector_sbert"] if sbert else []) + (["llm_judge"] if judge else [])
    proofs = {m: 0 for m in methods}
    clean_pred_clean = {m: 0 for m in methods}
    for r in rows:
        for m in methods:
            if r["pred"].get(m) is False:
                clean_pred_clean[m] += 1
        if r["info"]["custody_proof_of_absence"]:
            proofs["custody"] += 1
        if r["pred"]["sql_cte"] is False:
            proofs["sql_cte"] += 1   # the recursive CTE has no depth bound: it completed
    families = sorted({r["family"] for r in rows}, key=lambda f: (f[0] != "D", f))
    per_family = {f: {m: round(sum(bool(r["pred"].get(m)) for r in rows if r["family"] == f)
                               / max(1, sum(r["family"] == f for r in rows)), 3)
                      for m in methods} for f in families}
    llm_cost = None
    if judge is not None:
        toks_in = [u.get("input_tokens") or 0 for r in rows for u in r["info"].get("llm", {})
                   .get("usage", [])]
        toks_out = [u.get("output_tokens") or 0 for r in rows for u in r["info"].get("llm", {})
                    .get("usage", [])]
        n = len(toks_in)
        llm_cost = {"model": judge.model, "decisions": n,
                    "mean_input_tokens": round(sum(toks_in) / n, 1) if n else None,
                    "mean_output_tokens": round(sum(toks_out) / n, 1) if n else None,
                    "price_in_per_mtok": a.llm_price_in, "price_out_per_mtok": a.llm_price_out,
                    "usd_per_decision": (round((sum(toks_in) * a.llm_price_in
                                                + sum(toks_out) * a.llm_price_out) / 1e6 / n, 6)
                                         if n and a.llm_price_in is not None
                                         and a.llm_price_out is not None else None)}
    result = {
        "command": "python -m bench.run_correctness " + " ".join(argv or []),
        "machine": machine_info(backend),
        "config": {"variants": a.variants, "seed": a.seed, "tau": TAU, "top_k": TOP_K,
                   "families": a.families, "repeats": a.repeats,
                   "cases": len(rows), "dangerous": sum(r["label"] == "dangerous" for r in rows),
                   "clean": sum(r["label"] == "clean" for r in rows),
                   "chain_sweep": CHAIN_SWEEP},
        "store": {"datums": len(ex.docs), "untrusted_docs": len(untrusted),
                  "vector_corpus_docs": len(corpus),
                  "derived_from_edges": len(ex.edges), "record_ms": round(build_ms, 1),
                  "sql_build_ms": round(sql_build, 1),
                  "tfidf_build_ms": round(vec.build_ms, 1), "lsa_build_ms": round(lsa.build_ms, 1)},
        "skipped": skipped,
        "methods": {m: {**confusion(rows, m), "latency": summary(lat[m]),
                        "negatives_returned": clean_pred_clean[m],
                        "negatives_with_proof": proofs.get(m, 0)} for m in methods},
        "payload_latency": summary(lat["payload_custody"]),
        "llm_cost": llm_cost,
        "tau_sweep": {str(t): confusion(rows, f"vector_tfidf@{t}") for t in TAU_SWEEP},
        "custody_outcomes": {o: sum(r["info"]["custody_outcome"] == o for r in rows)
                             for o in ("PATH_FOUND", "NO_PATH", "INDETERMINATE")},
        "per_family_flag_rate": per_family,
        "rows": rows,
    }
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    (out / "correctness.json").write_text(json.dumps(result, indent=1))
    (out / "correctness.md").write_text(render(result, methods))
    print(render(result, methods))
    return 0


def render(r: dict, methods: List[str]) -> str:
    m = r["machine"]
    lines = [f"# Correctness benchmark (generated {m['date_utc']})", "",
             f"`{r['command'].strip()}` · {r['config']['cases']} cases "
             f"({r['config']['dangerous']} dangerous / {r['config']['clean']} clean), "
             f"seed {r['config']['seed']} · {m['backend']}, Python {m['python']}, "
             f"{m['cpu']} ×{m['cpus']}", "",
             "| method | TP | FN | TN | FP | recall | false-positive rate | negatives returned "
             "| negatives that are proofs | median latency | p95 |",
             "|---|---|---|---|---|---|---|---|---|---|---|"]
    for k in methods:
        x = r["methods"][k]
        lat = x["latency"]
        lines.append(f"| {k} | {x['TP']} | {x['FN']} | {x['TN']} | {x['FP']} | {x['recall']} | "
                     f"{x['false_positive_rate']} | {x['negatives_returned']} | "
                     f"{x['negatives_with_proof']} | {lat.get('median_ms')} ms | "
                     f"{lat.get('p95_ms')} ms |")
    if r["skipped"]:
        lines += ["", "Not run: " + "; ".join(f"{k}: {v}" for k, v in r["skipped"].items())]
    lines += ["", f"Custody outcomes: {r['custody_outcomes']}", "",
              "Fraction of cases flagged, per family (dangerous families should be 1.0, clean "
              "ones 0.0):", "",
              "| family | " + " | ".join(methods) + " |",
              "|---|" + "---|" * len(methods)]
    for f, v in r["per_family_flag_rate"].items():
        lines.append(f"| {f} | " + " | ".join(str(v[k]) for k in methods) + " |")
    lines += ["", f"vector_tfidf threshold sweep (top-{r['config']['top_k']}; τ={r['config']['tau']} "
              "used above was fixed before the first run):", "",
              "| τ | TP | FN | TN | FP |", "|---|---|---|---|---|"]
    for t, x in r["tau_sweep"].items():
        lines.append(f"| {t} | {x['TP']} | {x['FN']} | {x['TN']} | {x['FP']} |")
    split = [x for x in r["rows"] if x["family"] == "D_split_source"]
    if split:
        lines += ["", "Split-source cases (destination assembled from two untrusted sources; "
                  "no document contains it): every untrusted root Custody traced the destination "
                  "to (complete search), whether the routes are independent (verified: "
                  "node-disjoint after the argument), and what the edge-free baselines "
                  "concluded.", "",
                  "| case | destination | Custody roots | routes | string_exact | string_host "
                  "| vector_tfidf (top hit) |", "|---|---|---|---|---|---|---|"]
        for x in split:
            top = x["info"]["vector_top"][0] if x["info"]["vector_top"] else None
            lines.append(f"| {x['case']} | `{x['destination']}` | "
                         f"{len(x['info']['custody_untrusted_roots'])}: "
                         f"{', '.join(x['info']['custody_untrusted_roots'])} | "
                         f"{x['info'].get('custody_routes')} | "
                         f"{x['pred']['string_exact']} | {x['pred']['string_host']} | "
                         f"{x['pred']['vector_tfidf']} ({top}) |")
    s = r["store"]
    lines += ["", f"Store: {s['datums']} Datums ({s['untrusted_docs']} from untrusted sources), "
              f"{s['derived_from_edges']} DERIVED_FROM edges; vector corpus {s['vector_corpus_docs']} "
              "documents (external docs, user messages, memories, messages). Index build: SQLite "
              f"{s['sql_build_ms']} ms, TF-IDF {s['tfidf_build_ms']} ms (not in per-query "
              "latency). Custody latency is a full Guard check (integrity + confidentiality + "
              "binding, embedded FalkorDB, decisions not recorded)."]
    return "\n".join(lines) + "\n"


if __name__ == "__main__":
    raise SystemExit(main())
