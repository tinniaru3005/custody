# Benchmark hypotheses and falsification conditions

Written on 2026-10-06 **before** the first run of the v2 benchmark (330 cases), and not
edited afterwards except to link the results. The results, including any hypothesis that
failed, are in [results/REPORT.md](results/REPORT.md).

## What this benchmark can and cannot show

> **Circularity caveat.** The synthetic generator creates the ground-truth causal history,
> and Custody's Recorder records that same history as provenance edges. A method that reads
> those edges is being scored against labels derived from the process that wrote them.
> It would therefore be circular to conclude "graphs infer attacks better than RAG".

The question the benchmark answers instead:

> **If provenance is recorded, how much does explicit provenance help compared with
> techniques that try to reconstruct influence from content, and how suitable is FalkorDB
> for querying that provenance?**

Consequences we accept up front:

- Custody's correctness on in-scope categories is close to guaranteed by construction. Its
  interesting failures are the ones the recording *cannot* express (implicit flows) or
  over-states (over-approximation), and those are included on purpose.
- The recursive SQL CTE reads the same edges and is expected to match FalkorDB on
  correctness case for case. That is not a thesis threat; it means the value is in
  *recording* provenance, not in a particular database.
- Whether real agents' provenance can be recorded completely is not tested here (no real
  LLM traffic). See F4.

## Hypotheses (expected outcomes)

| # | Hypothesis | How it is measured |
|---|---|---|
| H1 | On in-scope attack categories Custody's recall is ≥ 0.95, and its false-escalation rate on content decoys (identical bytes from a trusted source, semantic decoy, lexical decoy, unrelated clean) is ≤ 0.05. | per-category recall / false-escalation |
| H2 | The best content-only method (string, host, TF-IDF or LSA retrieval at its **best** threshold and k chosen with hindsight, multi-hop retrieval) has F1 at least 0.10 below Custody on the in-scope set. | F1, PR sweep |
| H3 | Exact-string matching detects ~0 % of paraphrase-laundered destinations; retrieval detects fewer paraphrased than verbatim ones; methods that only see the acting context window (keyword scan, LLM judge) lose the attack once one or more agents sit between the page and the actor. | paraphrase-depth chart |
| H4 | The recursive SQL CTE agrees with Custody on every case. | agreement count |
| H5 | Custody, SQL, string and vector methods return one distinct verdict per case across repeated identical runs; an LLM judge returns more than one on some cases. | distinct verdicts over repeats |
| H6 | Every "nothing dangerous" from Custody is a completed traversal; its negative predictive value is 1.0 on in-scope categories. Content methods' NPV is < 0.9 and their negatives are absence of evidence. | negative-claim validity |
| H7 | A full Guard check on the case graphs has p95 < 100 ms; a 10k fan-in completes under the shipped 2 s limit; 100k fan-in does not (fail closed). | latency tables |
| H8 | The depth-bounded `*0..25` Cypher pattern misses the 26- and 40-hop chains. | deep-chain category |
| H9 | Custody flags every transformed secret payload; a decoding DLP catches identity, truncation, base64 and hex but not reversal or dash-splitting; Custody falsely flags agent-written summaries produced while a secret was in context (over-approximation). | payload table |

## Falsification / weakening conditions

If any of these happen they are reported in REPORT.md, not hidden.

| # | Condition | Effect on the thesis |
|---|---|---|
| F1 | A string + vector baseline (any operating point, including one picked with hindsight) comes within **0.05 F1** of Custody on the in-scope set. | Explicit provenance adds little over content methods on this data. |
| F2 | An LLM judge is ≥ 0.95 accurate across categories, gives the same verdict in ≥ 9/10 repeated runs per case, and its BLOCK rate moves ≤ 0.05 under the approval-claim injection. | A judge is a practical alternative; determinism is the main remaining argument. |
| F3 | FalkorDB Guard p50 exceeds 1 s, or the search fails to complete under shipped limits, at realistic fan-in (≤ 10k ancestors). | FalkorDB unsuitable at realistic scale in this design. |
| F4 | A genuine LLM recording reveals a dependency (an output using information from outside its recorded context) that the Recorder failed to capture. | The completeness assumption behind every negative claim is wrong. |
| F5 | Custody and the recursive CTE disagree on any case. | A bug in one of them (not a thesis threat, but must be explained). |

Status when written: F2 and F4 **cannot be tested in the benchmark environment** (no
`ANTHROPIC_API_KEY`, no genuine LLM recording). They are reported as untested, not as
passed.
