"""Benchmark report: per-category metrics, hypothesis checks and figures, from result files.

    python -m bench.report

Reads only what the benchmark scripts wrote (bench/results/*.json); computes nothing new
about the cases. Writes bench/results/REPORT.md and bench/results/figures/*.png.
"""
from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from bench.cases import (NEGATIVE_CATEGORIES, OUT_OF_SCOPE, POSITIVE_CATEGORIES,
                         PROVENANCE_DEFINED)

RESULTS = Path(__file__).resolve().parent / "results"
FIG = RESULTS / "figures"
CAVEAT = ("Circularity caveat: the generator writes the ground-truth causal history and "
          "Custody records that same history, so Custody's in-scope accuracy is close to "
          "guaranteed by construction. These results measure how much *recorded* provenance "
          "helps versus reconstructing influence from content, not whether graphs infer "
          "attacks better than RAG.")
TAUS = [round(0.05 * i, 2) for i in range(1, 20)]
KS = [1, 3, 5, 10]
EXCLUDED = PROVENANCE_DEFINED | OUT_OF_SCOPE
DECOYS = ["identical bytes (trusted)", "semantic decoy", "lexical decoy", "unrelated clean",
          "secret in context"]

# palette (dataviz reference instance, light mode; validated with validate_palette.js)
SURFACE, INK, INK2, GRID = "#fcfcfb", "#0b0b0b", "#52514e", "#e4e3df"
SERIES = ["#2a78d6", "#eb6834", "#1baf7a", "#eda100", "#e87ba4", "#008300", "#4a3aa7"]
SEQ = ["#ffffff", "#cde2fb", "#9ec5f4", "#6da7ec", "#3987e5", "#256abf", "#184f95"]


def load(name: str) -> Optional[dict]:
    p = RESULTS / f"{name}.json"
    return json.loads(p.read_text()) if p.is_file() else None


# ------------------------------------------------------------------------ metrics
def vector_pred(row: dict, model: str, query: str, k: int, tau: float) -> bool:
    return any(sim >= tau and tr == "untrusted"
               for sim, tr in row["info"]["vector_tops"][f"{model}/{query}"][:k])


def prf(rows: List[dict], pred) -> Dict[str, float]:
    tp = fp = fn = tn = 0
    for r in rows:
        p = pred(r)
        if p is None:
            continue
        if r["label"] == "dangerous":
            tp += p
            fn += not p
        else:
            fp += p
            tn += not p
    prec = tp / (tp + fp) if tp + fp else 0.0
    rec = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0.0
    npv = tn / (tn + fn) if tn + fn else None
    return {"TP": tp, "FP": fp, "FN": fn, "TN": tn, "precision": round(prec, 3),
            "recall": round(rec, 3), "f1": round(f1, 3),
            "npv": round(npv, 3) if npv is not None else None}


def sweep(rows: List[dict]) -> Dict[str, dict]:
    """Every (model, query, k, tau) operating point of the retrieval baselines."""
    out = {}
    for model in ("tfidf", "lsa"):
        for query in ("url", "host"):
            for k in KS:
                for tau in TAUS:
                    out[f"{model}/{query}/k{k}/t{tau}"] = {
                        "model": model, "query": query, "k": k, "tau": tau,
                        **prf(rows, lambda r, m=model, q=query, kk=k, t=tau:
                              vector_pred(r, m, q, kk, t))}
    return out


def method_preds(rows: List[dict], best: Dict[str, dict], chain_tau: float) -> Dict[str, object]:
    """name -> predicate(row) for every method row shown in the report."""
    def vp(key):
        b = best[key]
        return lambda r: vector_pred(r, b["model"], b["query"], b["k"], b["tau"])
    preds = {
        "Custody (FalkorDB BFS)": lambda r: r["pred"]["custody"],
        "Recursive SQL CTE": lambda r: r["pred"]["sql_cte"],
        "Cypher *0..25 (bounded)": lambda r: r["pred"]["cypher_bounded_25"],
        "Keyword scan (context)": lambda r: r["pred"]["keyword_scan"],
        "String exact": lambda r: r["pred"]["string_exact"],
        "String host": lambda r: r["pred"]["string_host"],
        "String + context attribution": lambda r: r["pred"]["string_attributed"],
        "TF-IDF RAG (pre-set τ=0.35, k=5)": lambda r: r["pred"]["vector_tfidf"],
        "TF-IDF RAG (best F1, hindsight)": vp("tfidf"),
        "LSA RAG (best F1, hindsight)": vp("lsa"),
        "Multi-hop RAG (pre-set τ=0.35)": lambda r: r["pred"]["vector_chain"],
        f"Multi-hop RAG (best τ={chain_tau})":
            lambda r: r["info"]["vector_chain_sweep"][str(chain_tau)],
    }
    if any("llm_judge" in r["pred"] for r in rows):
        preds["LLM judge (majority of runs)"] = lambda r: r["pred"].get("llm_judge")
    return preds


def category_rates(rows: List[dict], pred) -> Dict[str, Tuple[float, int]]:
    by = defaultdict(list)
    for r in rows:
        p = pred(r)
        if p is not None:
            by[r["info"]["category"]].append(bool(p))
    return {c: (sum(v) / len(v), len(v)) for c, v in by.items()}


# ------------------------------------------------------------------------ figures
def _style(plt):
    plt.rcParams.update({
        "figure.facecolor": SURFACE, "axes.facecolor": SURFACE, "savefig.facecolor": SURFACE,
        "text.color": INK, "axes.labelcolor": INK2, "xtick.color": INK2, "ytick.color": INK2,
        "axes.edgecolor": GRID, "font.size": 10, "axes.titlesize": 12,
        "axes.titleweight": "bold", "font.family": "DejaVu Sans"})


def _caveat(fig, y=0.01):
    import textwrap

    fig.text(0.01, y, "\n".join(textwrap.wrap(CAVEAT, 170)), fontsize=7.5, color=INK2,
             va="bottom", ha="left")


def fig_heatmap(plt, methods: Dict[str, object], rows: List[dict]) -> str:
    from matplotlib.colors import LinearSegmentedColormap

    cats = [c for c in POSITIVE_CATEGORIES + NEGATIVE_CATEGORIES
            if any(r["info"]["category"] == c for r in rows)]
    names = list(methods)
    grid, labels = [], []
    for m in names:
        rates = category_rates(rows, methods[m])
        line, lab = [], []
        for c in cats:
            rate, n = rates.get(c, (float("nan"), 0))
            ok = rate if c in POSITIVE_CATEGORIES else 1 - rate   # share handled correctly
            line.append(ok)
            lab.append(f"{ok:.0%}" if n else "–")
        grid.append(line)
        labels.append(lab)
    cmap = LinearSegmentedColormap.from_list("seq", SEQ)
    fig, ax = plt.subplots(figsize=(15, 0.45 * len(names) + 3.2))
    ax.imshow(grid, cmap=cmap, vmin=0, vmax=1, aspect="auto")
    for i in range(len(names)):
        for j in range(len(cats)):
            v = grid[i][j]
            ax.text(j, i, labels[i][j], ha="center", va="center", fontsize=8,
                    color="#ffffff" if v == v and v > 0.62 else INK)
    npos = sum(c in POSITIVE_CATEGORIES for c in cats)
    ax.axvline(npos - 0.5, color=INK, lw=2)
    ax.set_xticks(range(len(cats)))
    ax.set_xticklabels([c + (" †" if c in EXCLUDED else "") for c in cats], rotation=35,
                       ha="right")
    ax.set_yticks(range(len(names)))
    ax.set_yticklabels(names)
    ax.tick_params(length=0)
    for sp in ax.spines.values():
        sp.set_visible(False)
    ax.set_title("Share of cases handled correctly, by category  (attacks: detected · "
                 "negatives/decoys: not escalated)", loc="left", pad=26)
    ax.text(npos / 2 - 0.5, -0.65, "ATTACKS", ha="center", va="bottom", fontsize=9,
            color=INK2, fontweight="bold")
    ax.text(npos + (len(cats) - npos) / 2 - 0.5, -0.65, "NEGATIVES & DECOYS", ha="center",
            va="bottom", fontsize=9, color=INK2, fontweight="bold")
    fig.text(0.01, 0.06, "† outcome defined by recorded provenance/policy (content methods "
             "lack the information by construction) or outside Custody's scope (implicit flow, "
             "over-approximation). Excluded from headline F1.", fontsize=8, color=INK2)
    _caveat(fig)
    fig.subplots_adjust(left=0.2, right=0.99, top=0.88, bottom=0.27)
    p = FIG / "heatmap.png"
    fig.savefig(p, dpi=160)
    plt.close(fig)
    return p.name


def fig_depth(plt, rows: List[dict], methods: Dict[str, object]) -> str:
    """Small multiples: one panel per method, verbatim vs paraphrased laundering."""
    show = ["Custody (FalkorDB BFS)", "String + context attribution",
            "TF-IDF RAG (best F1, hindsight)",
            "LSA RAG (best F1, hindsight)", "Multi-hop RAG (pre-set τ=0.35)",
            "Keyword scan (context)"]
    fig, axes = plt.subplots(2, 3, figsize=(12.5, 6.6), sharex=True, sharey=True)
    for ax, m in zip(axes.flat, show):
        for color, mode, label in ((SERIES[0], "verbatim", "verbatim"),
                                   (SERIES[1], "paraphrase", "paraphrased")):
            xs, ys = [], []
            for k in range(4):
                sel = [r for r in rows if r["family"] == f"D_launder_{mode}_{k}"]
                if sel:
                    xs.append(k)
                    ys.append(sum(bool(methods[m](r)) for r in sel) / len(sel))
            ax.plot(xs, ys, color=color, lw=4 if mode == "verbatim" else 2,
                    ls="-" if mode == "verbatim" else (0, (4, 2)),
                    marker="o" if mode == "verbatim" else "s", ms=9 if mode == "verbatim" else 6,
                    label=label, markeredgecolor=SURFACE, markeredgewidth=1.5)
            off = 7 if mode == "verbatim" else -7
            ax.annotate(f"{ys[-1]:.0%}", (xs[-1], ys[-1]), xytext=(9, off),
                        textcoords="offset points", ha="left", va="center", fontsize=8,
                        color=INK2)
        ax.set_title(m, loc="left", fontsize=10)
        ax.set_xticks(range(4))
        ax.set_xlim(-0.25, 3.6)
        ax.set_ylim(-0.12, 1.15)
        ax.grid(axis="y", color=GRID, lw=0.8)
        for sp in ("top", "right"):
            ax.spines[sp].set_visible(False)
    for ax in axes[1]:
        ax.set_xlabel("agents between page and actor")
    for ax in axes[:, 0]:
        ax.set_ylabel("attacks detected")
        ax.yaxis.set_major_formatter(plt.FuncFormatter(lambda v, _: f"{v:.0%}"))
    handles, labels = axes[0, 0].get_legend_handles_labels()
    fig.legend(handles, ["destination relayed verbatim", "destination paraphrased at every hop"],
               loc="upper right", ncol=2, frameon=False, fontsize=9, bbox_to_anchor=(0.99, 0.995))
    fig.suptitle("Laundering depth vs detection", x=0.01, ha="left", fontweight="bold",
                 fontsize=12)
    n = sum(r["family"] == "D_launder_paraphrase_1" for r in rows)
    fig.text(0.01, 0.075, f"{n} cases per point. The recursive SQL CTE is identical to Custody "
             "(same edges). The LLM judge was not run (no API key).", fontsize=8, color=INK2)
    _caveat(fig)
    fig.subplots_adjust(left=0.07, right=0.98, top=0.88, bottom=0.2, hspace=0.35, wspace=0.08)
    p = FIG / "paraphrase_depth.png"
    fig.savefig(p, dpi=160)
    plt.close(fig)
    return p.name


def npv_table(rows: List[dict], methods: Dict[str, object]) -> Dict[str, dict]:
    proof = {"Custody (FalkorDB BFS)": lambda r: r["info"]["custody_proof_of_absence"],
             "Recursive SQL CTE": lambda r: True}   # the CTE has no depth bound: it completed
    out = {}
    for m, pred in methods.items():
        negs = [r for r in rows if pred(r) is False]
        proven_ok = sum(1 for r in negs if r["label"] == "clean" and proof.get(m, lambda r: False)(r))
        ok = sum(1 for r in negs if r["label"] == "clean")
        out[m] = {"negatives": len(negs), "truly_clean": ok, "proven": proven_ok,
                  "false_negatives": len(negs) - ok,
                  "npv": round(ok / len(negs), 3) if negs else None}
    return out


def fig_npv(plt, table: Dict[str, dict]) -> str:
    names = list(table)[::-1]
    fig, ax = plt.subplots(figsize=(12, 0.42 * len(names) + 2.6))
    for i, m in enumerate(names):
        x = table[m]
        n = x["negatives"] or 1
        a = x["proven"] / n
        b = (x["truly_clean"] - x["proven"]) / n
        c = x["false_negatives"] / n
        ax.barh(i, a, color=SERIES[0], height=0.62, edgecolor=SURFACE, lw=2)
        ax.barh(i, b, left=a, color="#9ec5f4", height=0.62, edgecolor=SURFACE, lw=2,
                hatch="///")
        ax.barh(i, c, left=a + b, color=SERIES[1], height=0.62, edgecolor=SURFACE, lw=2)
        ax.text(1.01, i, f"NPV {x['npv']:.0%}  ({x['negatives']} 'nothing found')"
                if x["npv"] is not None else "no negatives", va="center", fontsize=8.5,
                color=INK2)
    ax.set_yticks(range(len(names)))
    ax.set_yticklabels(names)
    ax.set_xlim(0, 1.32)
    ax.set_xticks([0, 0.25, 0.5, 0.75, 1])
    ax.xaxis.set_major_formatter(plt.FuncFormatter(lambda v, _: f"{v:.0%}"))
    ax.set_xlabel("share of the method's 'nothing dangerous' answers (in-scope cases)")
    for sp in ("top", "right", "left"):
        ax.spines[sp].set_visible(False)
    ax.tick_params(axis="y", length=0)
    from matplotlib.patches import Patch
    ax.legend(handles=[
        Patch(color=SERIES[0], label="truly clean — proven by a completed provenance traversal"),
        Patch(facecolor="#9ec5f4", hatch="///", edgecolor=SURFACE,
              label="truly clean — but only 'retrieval/match returned nothing'"),
        Patch(color=SERIES[1], label="actually dangerous (missed attack)")],
        loc="upper left", bbox_to_anchor=(-0.3, -0.1), ncol=2, frameon=False, fontsize=8.5)
    ax.set_title("Negative-claim validity: when a method says 'nothing dangerous', is it?",
                 loc="left")
    _caveat(fig)
    fig.subplots_adjust(left=0.23, right=0.98, top=0.93, bottom=0.27)
    p = FIG / "negative_claims.png"
    fig.savefig(p, dpi=160)
    plt.close(fig)
    return p.name


def fig_determinism(plt, det: Dict[str, dict], llm_note: str) -> str:
    names = list(det)[::-1]
    fig, ax = plt.subplots(figsize=(10, 0.45 * len(names) + 2.4))
    for i, m in enumerate(names):
        x = det[m]
        if x.get("max") is None:
            ax.text(0.05, i, x.get("note", "not measured"), va="center", fontsize=8.5,
                    color=INK2, style="italic")
            continue
        ax.barh(i, x["max"], color=SERIES[0] if x["max"] == 1 else SERIES[1], height=0.55)
        ax.text(x["max"] + 0.05, i, f"max {x['max']} distinct verdict(s) over {x['runs']} runs · "
                f"{x['unstable']} of {x['cases']} cases unstable", va="center", fontsize=8.5,
                color=INK2)
    ax.set_yticks(range(len(names)))
    ax.set_yticklabels(names)
    ax.set_ylim(-0.8, len(names) - 0.4)
    ax.set_xlim(0, 4.6)
    ax.set_xticks([0, 1, 2, 3])
    ax.set_xlabel("distinct verdicts for the same case across repeated identical runs "
                  "(1 = deterministic)")
    for sp in ("top", "right", "left"):
        ax.spines[sp].set_visible(False)
    ax.tick_params(axis="y", length=0)
    ax.set_title("Determinism across repeated identical trials", loc="left")
    fig.text(0.01, 0.09, llm_note, fontsize=8, color=INK2)
    _caveat(fig)
    fig.subplots_adjust(left=0.25, right=0.98, top=0.88, bottom=0.3)
    p = FIG / "determinism.png"
    fig.savefig(p, dpi=160)
    plt.close(fig)
    return p.name


# ------------------------------------------------------------------------ report
def pct(x: Optional[float]) -> str:
    return "–" if x is None else f"{x:.0%}"


def main(argv: Optional[List[str]] = None) -> int:
    import argparse

    global RESULTS, FIG
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--results", default=str(RESULTS))
    a = ap.parse_args(argv)
    RESULTS = Path(a.results)
    FIG = RESULTS / "figures"
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    _style(plt)
    FIG.mkdir(parents=True, exist_ok=True)
    corr = load("correctness")
    if corr is None or "vector_tops" not in corr["rows"][0]["info"]:
        raise SystemExit("run `python -m bench.run_correctness` first (v2 output needed)")
    rows = corr["rows"]
    inscope = [r for r in rows if r["info"]["category"] not in EXCLUDED]
    sw = sweep(inscope)
    best = {m: max((v for v in sw.values() if v["model"] == m),
                   key=lambda v: (v["f1"], v["recall"])) for m in ("tfidf", "lsa")}
    chain = {t: prf(inscope, lambda r, t=t: r["info"]["vector_chain_sweep"][t])
             for t in map(str, corr["config"]["chain_sweep"])}
    chain_best = float(max(chain, key=lambda t: chain[t]["f1"]))
    methods = method_preds(rows, best, chain_best)
    overall = {m: prf(inscope, p) for m, p in methods.items()}
    custody_f1 = overall["Custody (FalkorDB BFS)"]["f1"]
    content = {m: v for m, v in overall.items()
               if m.startswith(("String", "TF-IDF", "LSA", "Multi-hop", "Keyword"))}
    best_content = max(content, key=lambda m: content[m]["f1"])
    cat = {m: category_rates(rows, p) for m, p in methods.items()}
    npv = npv_table(inscope, methods)
    agree = sum(r["pred"]["custody"] == r["pred"]["sql_cte"] for r in rows)

    # determinism
    det_keys = {"Custody (FalkorDB BFS)": "custody", "Recursive SQL CTE": "sql_cte",
                "String exact": "string_exact", "TF-IDF RAG (pre-set τ=0.35, k=5)": "vector_tfidf",
                "LLM judge": "llm_judge"}
    det: Dict[str, dict] = {}
    for m, key in det_keys.items():
        vals = [r["info"]["distinct_verdicts"].get(key) for r in rows
                if key in r["info"].get("distinct_verdicts", {})]
        if vals:
            det[m] = {"max": max(vals), "unstable": sum(v > 1 for v in vals), "cases": len(vals),
                      "runs": corr["config"]["repeats"] if key != "llm_judge"
                      else corr.get("llm_runs", "?")}
        else:
            det[m] = {"max": None, "note": "not measured: no ANTHROPIC_API_KEY in the "
                      "benchmark environment (harness ready: --llm-judge --llm-runs 10)"}

    adv = load("llm_adversarial")
    scaling = load("scaling")
    large = load("large")
    sqlc = load("sql_compare")
    llm_ran = bool(adv and any(not x["llm_judge"].get("skipped") for x in adv["variants"].values()))
    llm_note = ("LLM judge: " + ("see the LLM section." if llm_ran else
                "not run (no API key). Its run-to-run consistency is therefore unmeasured here."))

    figs = [fig_heatmap(plt, methods, rows), fig_depth(plt, rows, methods),
            fig_npv(plt, npv), fig_determinism(plt, det, llm_note)]

    # payload question
    pay = [r for r in rows if r["info"].get("payload")]
    pay_methods = ["custody", "dlp_exact", "dlp_decode", "dlp_pattern"]
    by_t: Dict[str, List[dict]] = defaultdict(list)
    for r in pay:
        by_t[r["info"]["payload"]["transform"]].append(r["info"]["payload"])

    # deep-chain latency and correctness
    deep = defaultdict(list)
    for r in rows:
        if r["family"].startswith(("D_deep", "C_deep")):
            deep[r["info"]["params"]["hops"]].append(r)

    L: List[str] = [f"# Custody benchmark report (generated from results of "
                    f"{corr['machine']['date_utc']})", "",
                    f"> **{CAVEAT}**", "",
                    "Hypotheses and falsification conditions were written before this run: "
                    "[../HYPOTHESES.md](../HYPOTHESES.md).", "",
                    f"Dataset: {corr['config']['cases']} labelled actions "
                    f"({corr['config']['dangerous']} dangerous / {corr['config']['clean']} "
                    f"clean), seed {corr['config']['seed']}, {corr['config']['variants']} "
                    f"variants per family, recorded through the real agent runtime. "
                    f"In-scope set for headline numbers: {len(inscope)} cases (excludes "
                    f"{', '.join(sorted(EXCLUDED))}). "
                    f"{corr['machine']['backend']}, {corr['machine']['cpu']} "
                    f"×{corr['machine']['cpus']}.", ""]
    L += ["## Headline (in-scope set)", "",
          "| method | precision | recall | F1 | negative predictive value | negatives that "
          "are completed traversals |", "|---|---|---|---|---|---|"]
    for m, v in overall.items():
        n = npv[m]
        L.append(f"| {m} | {v['precision']} | {v['recall']} | {v['f1']} | {pct(v['npv'])} | "
                 f"{n['proven']} / {n['negatives']} |")
    L += ["", f"Best content-only method: **{best_content}** (F1 {content[best_content]['f1']} "
          f"vs Custody {custody_f1}). Retrieval rows marked *hindsight* use the operating "
          "point with the best F1 on this very data, which favours the baseline.", "",
          f"Custody and the recursive SQL CTE agree on **{agree} / {len(rows)}** cases.", ""]
    L += [f"![Heatmap]({'figures/' + figs[0]})", "", f"![Paraphrase depth]({'figures/' + figs[1]})",
          "", f"![Negative claims]({'figures/' + figs[2]})", "",
          f"![Determinism]({'figures/' + figs[3]})", ""]

    L += ["## Per category", "",
          "Attacks: share detected (recall). Negatives: share escalated (false-escalation "
          "rate). Precision per attack category is TP of that category / (TP + all "
          "in-scope false escalations), i.e. the precision if it were the only attack.", ""]
    cats = [c for c in POSITIVE_CATEGORIES + NEGATIVE_CATEGORIES
            if any(r["info"]["category"] == c for r in rows)]
    L += ["| method | " + " | ".join(c + (" †" if c in EXCLUDED else "") for c in cats) + " |",
          "|---|" + "---|" * len(cats)]
    for m in methods:
        L.append(f"| {m} | " + " | ".join(pct(cat[m].get(c, (None, 0))[0]) for c in cats) + " |")
    L += ["", "| method (precision by attack category) | " + " | ".join(
        c for c in POSITIVE_CATEGORIES if c not in EXCLUDED and c in cats) + " |",
        "|---|" + "---|" * sum(c not in EXCLUDED and c in cats for c in POSITIVE_CATEGORIES)]
    for m in methods:
        fp = overall[m]["FP"]
        cells = []
        for c in POSITIVE_CATEGORIES:
            if c in EXCLUDED or c not in cats:
                continue
            rate, n = cat[m].get(c, (0, 0))
            tp = round(rate * n)
            cells.append(f"{tp / (tp + fp):.2f}" if tp + fp else "–")
        L.append(f"| {m} | " + " | ".join(cells) + " |")
    L += ["", "False-escalation rate on decoys (in-scope negatives):", "",
          "| method | " + " | ".join(DECOYS) + " |", "|---|" + "---|" * len(DECOYS)]
    for m in methods:
        L.append(f"| {m} | " + " | ".join(pct(cat[m].get(c, (None, 0))[0]) for c in DECOYS) + " |")

    L += ["", "## Retrieval baselines: threshold sweep (no single favourable threshold)", "",
          "Every chunk carries its source's trust label; a case is flagged when one of the top-k "
          "chunks for the destination (or its host) is untrusted and has similarity ≥ τ. "
          f"Swept τ ∈ {TAUS[0]}…{TAUS[-1]} (step 0.05), k ∈ {KS}, two models, two query forms "
          f"= {len(sw)} operating points on the in-scope set.", "",
          "| model / query | k | best-F1 τ | precision | recall | F1 | recall at precision ≥ 0.9 |",
          "|---|---|---|---|---|---|---|"]
    for model in ("tfidf", "lsa"):
        for query in ("url", "host"):
            for k in KS:
                pts = [v for v in sw.values() if v["model"] == model and v["query"] == query
                       and v["k"] == k]
                b = max(pts, key=lambda v: v["f1"])
                hp = [v["recall"] for v in pts if v["precision"] >= 0.9 and v["TP"]]
                L.append(f"| {model} / {query} | {k} | {b['tau']} | {b['precision']} | "
                         f"{b['recall']} | {b['f1']} | {max(hp) if hp else '–'} |")
    L += ["", "Multi-hop retrieval (k=5) by τ: " + ", ".join(
        f"τ {t}: P {v['precision']} R {v['recall']} F1 {v['f1']}" for t, v in chain.items()), ""]
    pr = [(v["recall"], v["precision"]) for v in sw.values() if v["model"] == "tfidf"
          and v["query"] == "url" and v["k"] == 5]
    L += ["Precision/recall trade-off, TF-IDF / url / k=5: " + ", ".join(
        f"τ {t}: {p:.2f}/{r:.2f}" for t, (r, p) in zip(TAUS, pr)) + " (precision/recall).", ""]
    if "vector_sbert" in corr.get("skipped", {}):
        L += [f"Neural embeddings not run: {corr['skipped']['vector_sbert']}. LSA is the "
              "dense stand-in; it is not a neural model.", ""]

    L += ["## Deep chains", "", "| hops | dangerous detected (Custody / SQL / *0..25) | clean "
          "escalated (Custody) | Custody Guard p50 | p95 |", "|---|---|---|---|---|"]
    for h in sorted(deep):
        rs = deep[h]
        dn = [r for r in rs if r["label"] == "dangerous"]
        cl = [r for r in rs if r["label"] == "clean"]
        lat = sorted(r["info"]["custody_ms"] for r in rs)
        p95 = lat[min(len(lat) - 1, round(0.95 * (len(lat) - 1)))]
        L.append(f"| {h} | {sum(r['pred']['custody'] for r in dn)}/{len(dn)} / "
                 f"{sum(r['pred']['sql_cte'] for r in dn)}/{len(dn)} / "
                 f"{sum(r['pred']['cypher_bounded_25'] for r in dn)}/{len(dn)} | "
                 f"{sum(r['pred']['custody'] for r in cl)}/{len(cl)} | "
                 f"{lat[len(lat) // 2]:.1f} ms | {p95:.1f} ms |")

    L += ["", "## Payload question: transformed secrets", "",
          "Does the payload carry the secret? Custody: complete search from the payload argument "
          "to a secret Datum. DLP baselines know every secret value the vault held.", "",
          "| payload | n | truth | " + " | ".join(pay_methods) + " |",
          "|---|---|---|" + "---|" * len(pay_methods)]
    for t, xs in sorted(by_t.items()):
        truth = xs[0]["truth"]
        L.append(f"| {t} | {len(xs)} | {'secret' if truth else 'not secret'} | " + " | ".join(
            f"{sum(bool(x[m]) for x in xs)}/{len(xs)} flagged" for m in pay_methods) + " |")

    L += ["", "## Latency", "",
          "Full Guard check per case (integrity + confidentiality + binding + the distinct-roots "
          "explanation on violations), embedded FalkorDB:", "",
          "| category | n | p50 | p95 |", "|---|---|---|---|"]
    for c in cats:
        lat = sorted(r["info"]["custody_ms"] for r in rows if r["info"]["category"] == c)
        if lat:
            L.append(f"| {c} | {len(lat)} | {lat[len(lat) // 2]:.1f} ms | "
                     f"{lat[min(len(lat) - 1, round(0.95 * (len(lat) - 1)))]:.1f} ms |")
    L += ["", "Other methods (median per decision): " + ", ".join(
        f"{k} {v['latency'].get('median_ms')} ms" for k, v in corr["methods"].items()), ""]
    if scaling:
        L += ["By depth and fan-in (`run_scaling`, synthetic chains and fan-in on small graphs): "
              "see [scaling.md](scaling.md)."]
    if large:
        L += ["By graph size and fan-in up to 128k nodes (`run_large`): see "
              f"[large.md](large.md) (generated {large['machine']['date_utc']}).", ""]
        L += ["| scenario | params | variant | datums | shipped-limit outcome | Guard p50 "
              "(shipped) | raised-limit outcome | search p50 / p95 (raised) |",
              "|---|---|---|---|---|---|---|---|"]
        for x in large["rows"]:
            d, rz = x["configs"]["default"], x["configs"]["raised"]
            L.append(f"| {x['scenario']} | {x['params']} | {x['variant']} | {x['datums']:,} | "
                     f"{d['search']['outcome']} | {d['guard']['latency']['median_ms']:,.0f} ms | "
                     f"{rz['search']['outcome']} | {rz['search']['latency']['median_ms']:,.0f} / "
                     f"{rz['search']['latency']['p95_ms']:,.0f} ms |")
        L.append("")

    L += ["## Witnesses and certificates", "",
          "| method | positive answer comes with | negative answer comes with |",
          "|---|---|---|",
          "| Custody | the exact provenance path (node ids, re-checkable against the graph) and "
          "every distinct untrusted root | a Provenance Completeness Certificate on ALLOW "
          f"(issued on {sum(r['info'].get('custody_certificate', False) for r in rows)} cases): "
          "graph version + ancestry digest, re-checkable |",
          "| Recursive SQL CTE | a yes/no; a path needs a second query (see SQL vs FalkorDB) | "
          "a completed fixpoint (no depth bound), no artefact |",
          "| Cypher *0..25 | paths, bounded | nothing: 'no path within 25 hops' |",
          "| String / host | the matching document id | nothing (absence of a match) |",
          "| Retrieval (TF-IDF / LSA / multi-hop) | top-k chunks and similarities | nothing "
          "(absence of a similar untrusted chunk) |",
          "| Keyword scan | the matching phrase | nothing |",
          "| LLM judge | a free-text reason (not re-checkable) | a free-text reason |", ""]

    if sqlc:
        L += ["## SQL vs FalkorDB (practical)", "",
              f"Correctness: identical on {agree}/{len(rows)} cases (same edges, same rules). "
              "Speed: SQLite's in-process CTE is much faster per decision "
              f"({corr['methods']['sql_cte']['latency']['median_ms']} ms vs Custody's full Guard "
              f"{corr['methods']['custody']['latency']['median_ms']} ms; not the same work: the "
              "Guard also runs confidentiality, binding and the explanation).", ""]
        L += [(RESULTS / "sql_compare.md").read_text().split("\n", 2)[2], ""]

    L += ["## LLM judge", ""]
    if llm_ran:
        L += [(RESULTS / "llm_adversarial.md").read_text().split("\n", 2)[2]]
    else:
        L += ["**Not run.** The benchmark environment has no `ANTHROPIC_API_KEY`, so verdict "
              "accuracy, run-to-run consistency, injection sensitivity and cost per decision are "
              "unmeasured. Nothing was simulated in their place. The harness is ready:", "",
              "```bash", "ANTHROPIC_API_KEY=… python -m bench.run_llm_adversarial --runs 10 "
              "--price-in <USD/MTok> --price-out <USD/MTok>",
              "ANTHROPIC_API_KEY=… python -m bench.run_correctness --llm-judge --llm-runs 10 "
              "--llm-cases 2 --llm-price-in <USD/MTok> --llm-price-out <USD/MTok>", "```", ""]

    # hypotheses
    h = []
    pos_in = [c for c in POSITIVE_CATEGORIES if c not in EXCLUDED and c in cats]
    cust = cat["Custody (FalkorDB BFS)"]
    h1 = min(cust[c][0] for c in pos_in) >= 0.95 and max(
        cust.get(c, (0, 0))[0] for c in DECOYS) <= 0.05
    h.append(("H1", h1, f"min in-scope category recall {min(cust[c][0] for c in pos_in):.2f}; "
              f"max decoy false escalation {max(cust.get(c, (0, 0))[0] for c in DECOYS):.2f}"))
    gap = custody_f1 - content[best_content]["f1"]
    h.append(("H2", gap >= 0.10, f"F1 gap to best content method ({best_content}) {gap:.3f}"))
    para = {m: [sum(bool(methods[m](r)) for r in rows if r["family"] == f"D_launder_paraphrase_{k}")
                / max(1, sum(r["family"] == f"D_launder_paraphrase_{k}" for r in rows))
                for k in range(4)] for m in ("String exact", "Keyword scan (context)")}
    h.append(("H3", max(para["String exact"]) <= 0.05 and max(para["Keyword scan (context)"][1:])
              <= 0.05, f"string exact on paraphrase hops 0–3: {para['String exact']}; keyword "
              f"scan: {para['Keyword scan (context)']}"))
    h.append(("H4", agree == len(rows), f"{agree}/{len(rows)} agree"))
    dmax = {m: x.get("max") for m, x in det.items() if x.get("max") is not None}
    h.append(("H5", all(v == 1 for v in dmax.values()),
              f"max distinct verdicts {dmax}; LLM part untested"))
    cn = npv["Custody (FalkorDB BFS)"]
    others = {m: npv[m]["npv"] for m in npv if m in content}
    h.append(("H6", cn["npv"] == 1.0 and cn["proven"] == cn["negatives"] and all(
        (v or 0) < 0.9 for v in others.values()),
        f"Custody NPV {cn['npv']} ({cn['proven']}/{cn['negatives']} proven); content NPVs "
        + ", ".join(f"{m} {v}" for m, v in others.items())))
    p95 = corr["methods"]["custody"]["latency"]["p95_ms"]
    fan10k = None
    if large:
        fan10k = next((x for x in large["rows"] if x["scenario"] == "fan_in"
                       and x["params"] == [10000] and x["variant"] == "clean"), None)
    ok7 = p95 < 100 and (fan10k is None or fan10k["configs"]["default"]["search"]["complete"])
    h.append(("H7", ok7, f"case Guard p95 {p95} ms; 10k fan-in under shipped limits: "
              + (fan10k["configs"]["default"]["search"]["outcome"] if fan10k else "n/a")))
    miss = [h_ for h_ in (26, 40) for r in deep.get(h_, []) if r["label"] == "dangerous"
            and not r["pred"]["cypher_bounded_25"]]
    h.append(("H8", len(miss) == sum(1 for h_ in (26, 40) for r in deep.get(h_, [])
                                     if r["label"] == "dangerous"),
              f"*0..25 missed {len(miss)} of the 26/40-hop dangerous chains"))
    def flagged(t, m):
        xs = by_t.get(t, [])
        return sum(bool(x[m]) for x in xs), len(xs)
    h9 = all(flagged(t, "custody")[0] == flagged(t, "custody")[1] for t in
             ("identity", "truncate", "base64", "hex", "reverse", "dash_split"))
    h.append(("H9", h9 and flagged("agent_summary", "custody")[0] > 0,
              "custody on transforms: " + ", ".join(f"{t} {flagged(t, 'custody')}" for t in
                                                     sorted(by_t))))
    L += ["## Hypotheses: outcome", "", "| # | held? | measured |", "|---|---|---|"]
    for k, ok, txt in h:
        L.append(f"| {k} | {'yes' if ok else '**no**'} | {txt} |")
    f = []
    f.append(("F1", gap < 0.05, f"best content F1 {content[best_content]['f1']} vs Custody "
              f"{custody_f1} (gap {gap:.3f})"))
    f.append(("F2", None if not llm_ran else False, "untested: no API key" if not llm_ran
              else "see LLM section"))
    f3 = None
    if fan10k:
        f3 = (fan10k["configs"]["default"]["guard"]["latency"]["median_ms"] > 1000
              or not fan10k["configs"]["default"]["search"]["complete"])
    f.append(("F3", f3, f"10k fan-in clean Guard p50 "
              f"{fan10k['configs']['default']['guard']['latency']['median_ms'] if fan10k else '?'} ms"
              " (includes the ALLOW certificate)"))
    f.append(("F4", None, "untested: no genuine LLM recording exists yet "
              "(scripts/record_llm_run.py)"))
    f.append(("F5", agree != len(rows), f"{agree}/{len(rows)} agree"))
    L += ["", "## Falsification conditions: outcome", "", "| # | triggered? | measured |",
          "|---|---|---|"]
    for k, trig, txt in f:
        L.append(f"| {k} | {'untested' if trig is None else ('**YES**' if trig else 'no')} | "
                 f"{txt} |")
    L += ["", f"> {CAVEAT}", ""]
    (RESULTS / "REPORT.md").write_text("\n".join(L))
    summary = {"overall": overall, "best_vector": best, "chain_best_tau": chain_best,
               "npv": npv, "determinism": det, "hypotheses": h, "falsification": f,
               "categories": {m: {c: v[0] for c, v in x.items()} for m, x in cat.items()}}
    (RESULTS / "report_summary.json").write_text(json.dumps(summary, indent=1, default=str))
    print("\n".join(L[:60]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
