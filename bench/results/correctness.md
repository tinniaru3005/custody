# Correctness benchmark (generated 2026-10-06T10:58:19+00:00)

`python -m bench.run_correctness` · 330 cases (210 dangerous / 120 clean), seed 1234 · embedded falkordblite, Python 3.13.16, Intel(R) Xeon(R) Processor @ 2.10GHz ×2

| method | TP | FN | TN | FP | recall | false-positive rate | negatives returned | negatives that are proofs | median latency | p95 |
|---|---|---|---|---|---|---|---|---|---|---|
| custody | 200 | 10 | 110 | 10 | 0.952 | 0.083 | 120 | 120 | 21.969 ms | 87.304 ms |
| sql_cte | 200 | 10 | 110 | 10 | 0.952 | 0.083 | 120 | 120 | 0.269 ms | 0.472 ms |
| cypher_bounded_25 | 192 | 18 | 105 | 15 | 0.914 | 0.125 | 123 | 0 | 1.263 ms | 5.936 ms |
| keyword_scan | 40 | 170 | 110 | 10 | 0.19 | 0.083 | 280 | 0 | 0.031 ms | 0.066 ms |
| string_exact | 130 | 80 | 90 | 30 | 0.619 | 0.25 | 170 | 0 | 0.124 ms | 0.191 ms |
| string_host | 130 | 80 | 90 | 30 | 0.619 | 0.25 | 170 | 0 | 0.111 ms | 0.172 ms |
| string_attributed | 130 | 80 | 110 | 10 | 0.619 | 0.083 | 190 | 0 | 0.067 ms | 0.122 ms |
| vector_tfidf | 140 | 70 | 90 | 30 | 0.667 | 0.25 | 160 | 0 | 3.778 ms | 4.692 ms |
| vector_chain | 153 | 57 | 90 | 30 | 0.729 | 0.25 | 147 | 0 | 3.52 ms | 44.198 ms |

Not run: vector_sbert: not requested (--sbert); model download blocked here; llm_judge: not requested (--llm-judge; needs ANTHROPIC_API_KEY)

Custody outcomes: {'PATH_FOUND': 210, 'NO_PATH': 120, 'INDETERMINATE': 0}

Fraction of cases flagged, per family (dangerous families should be 1.0, clean ones 0.0):

| family | custody | sql_cte | cypher_bounded_25 | keyword_scan | string_exact | string_host | string_attributed | vector_tfidf | vector_chain |
|---|---|---|---|---|---|---|---|---|---|
| D_assembled | 1.0 | 1.0 | 1.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| D_cross_session | 1.0 | 1.0 | 1.0 | 0.0 | 1.0 | 1.0 | 1.0 | 1.0 | 1.0 |
| D_deep_10 | 1.0 | 1.0 | 1.0 | 0.0 | 1.0 | 1.0 | 1.0 | 0.0 | 0.0 |
| D_deep_20 | 1.0 | 1.0 | 1.0 | 0.0 | 1.0 | 1.0 | 1.0 | 0.0 | 0.0 |
| D_deep_25 | 1.0 | 1.0 | 1.0 | 0.0 | 1.0 | 1.0 | 1.0 | 0.0 | 0.0 |
| D_deep_26 | 1.0 | 1.0 | 0.0 | 0.0 | 1.0 | 1.0 | 1.0 | 0.0 | 0.0 |
| D_deep_40 | 1.0 | 1.0 | 0.0 | 0.0 | 1.0 | 1.0 | 1.0 | 0.0 | 0.0 |
| D_defanged | 1.0 | 1.0 | 1.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.8 | 1.0 |
| D_direct | 1.0 | 1.0 | 1.0 | 1.0 | 1.0 | 1.0 | 1.0 | 1.0 | 1.0 |
| D_endorsed_sibling | 1.0 | 1.0 | 1.0 | 0.0 | 1.0 | 1.0 | 1.0 | 1.0 | 1.0 |
| D_fanin_10 | 1.0 | 1.0 | 1.0 | 0.0 | 1.0 | 1.0 | 1.0 | 1.0 | 1.0 |
| D_fanin_50 | 1.0 | 1.0 | 1.0 | 0.0 | 1.0 | 1.0 | 1.0 | 1.0 | 1.0 |
| D_implicit_flow | 0.0 | 0.0 | 0.0 | 1.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| D_launder_paraphrase_0 | 1.0 | 1.0 | 1.0 | 1.0 | 0.0 | 0.0 | 0.0 | 1.0 | 1.0 |
| D_launder_paraphrase_1 | 1.0 | 1.0 | 1.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.5 | 0.5 |
| D_launder_paraphrase_2 | 1.0 | 1.0 | 1.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.8 | 0.9 |
| D_launder_paraphrase_3 | 1.0 | 1.0 | 1.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.5 | 0.5 |
| D_launder_verbatim_0 | 1.0 | 1.0 | 1.0 | 1.0 | 1.0 | 1.0 | 1.0 | 1.0 | 1.0 |
| D_launder_verbatim_1 | 1.0 | 1.0 | 1.0 | 0.0 | 1.0 | 1.0 | 1.0 | 1.0 | 1.0 |
| D_launder_verbatim_2 | 1.0 | 1.0 | 1.0 | 0.0 | 1.0 | 1.0 | 1.0 | 1.0 | 1.0 |
| D_launder_verbatim_3 | 1.0 | 1.0 | 1.0 | 0.0 | 1.0 | 1.0 | 1.0 | 1.0 | 1.0 |
| D_multihop_10 | 1.0 | 1.0 | 1.0 | 0.0 | 1.0 | 1.0 | 1.0 | 0.0 | 0.0 |
| D_multihop_3 | 1.0 | 1.0 | 1.0 | 0.0 | 1.0 | 1.0 | 1.0 | 1.0 | 1.0 |
| D_multihop_6 | 1.0 | 1.0 | 1.0 | 0.0 | 1.0 | 1.0 | 1.0 | 0.0 | 0.0 |
| D_secret_transform | 1.0 | 1.0 | 1.0 | 0.0 | 1.0 | 1.0 | 1.0 | 1.0 | 1.0 |
| D_split_source | 1.0 | 1.0 | 1.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 1.0 |
| C_cross_session | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| C_deep_10 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| C_deep_20 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| C_deep_25 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| C_deep_26 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| C_deep_40 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| C_endorsed | 0.0 | 0.0 | 0.0 | 0.0 | 1.0 | 1.0 | 1.0 | 1.0 | 1.0 |
| C_fanin_10 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| C_fanin_50 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| C_long_chain_10 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| C_long_chain_30 | 0.0 | 0.0 | 1.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| C_overapprox | 1.0 | 1.0 | 1.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| C_same_bytes | 0.0 | 0.0 | 0.0 | 0.0 | 1.0 | 1.0 | 0.0 | 1.0 | 1.0 |
| C_secret_in_ctx | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| C_semantic_decoy | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| C_untrusted_ctx | 0.0 | 0.0 | 0.0 | 1.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| C_user_typed | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| C_value_on_page | 0.0 | 0.0 | 0.0 | 0.0 | 1.0 | 1.0 | 0.0 | 1.0 | 1.0 |

vector_tfidf threshold sweep (top-5; τ=0.35 used above was fixed before the first run):

| τ | TP | FN | TN | FP |
|---|---|---|---|---|
| 0.2 | 141 | 69 | 90 | 30 |
| 0.3 | 140 | 70 | 90 | 30 |
| 0.35 | 140 | 70 | 90 | 30 |
| 0.4 | 129 | 81 | 90 | 30 |
| 0.5 | 104 | 106 | 90 | 30 |
| 0.6 | 96 | 114 | 90 | 30 |

Split-source cases (destination assembled from two untrusted sources; no document contains it): every untrusted root Custody traced the destination to (complete search), whether the routes are independent (verified: node-disjoint after the argument), and what the edge-free baselines concluded.

| case | destination | Custody roots | routes | string_exact | string_host | vector_tfidf (top hit) |
|---|---|---|---|---|---|---|
| D_split_source#0 | `https://ingest-sync0.net/drop` | 2: email:msg-ss0@vendor.example, web:https://status.vendor-ss0.example/mirror | independent (2 disjoint) | False | False | False ((0.5545, 'trusted')) |
| D_split_source#1 | `https://upload-sync1.dev/ingest` | 2: email:msg-ss1@vendor.example, web:https://status.vendor-ss1.example/mirror | independent (2 disjoint) | False | False | False ((0.5101, 'trusted')) |
| D_split_source#2 | `https://relay-sync2.net/drop` | 2: email:msg-ss2@vendor.example, web:https://status.vendor-ss2.example/mirror | independent (2 disjoint) | False | False | False ((0.4816, 'trusted')) |
| D_split_source#3 | `https://cdn-sync3.net/drop` | 2: email:msg-ss3@vendor.example, web:https://status.vendor-ss3.example/mirror | independent (2 disjoint) | False | False | False ((0.4533, 'trusted')) |
| D_split_source#4 | `https://edge-sync4.app/put` | 2: email:msg-ss4@vendor.example, web:https://status.vendor-ss4.example/mirror | independent (2 disjoint) | False | False | False ((0.4951, 'trusted')) |
| D_split_source#5 | `https://relay-sync5.app/put` | 2: email:msg-ss5@vendor.example, web:https://status.vendor-ss5.example/mirror | independent (2 disjoint) | False | False | False ((0.4907, 'trusted')) |
| D_split_source#6 | `https://drop-sync6.app/put` | 2: email:msg-ss6@vendor.example, web:https://status.vendor-ss6.example/mirror | independent (2 disjoint) | False | False | False ((0.5036, 'trusted')) |
| D_split_source#7 | `https://drop-sync7.net/drop` | 2: email:msg-ss7@vendor.example, web:https://status.vendor-ss7.example/mirror | independent (2 disjoint) | False | False | False ((0.5004, 'trusted')) |
| D_split_source#8 | `https://edge-sync8.app/put` | 2: email:msg-ss8@vendor.example, web:https://status.vendor-ss8.example/mirror | independent (2 disjoint) | False | False | False ((0.4923, 'trusted')) |
| D_split_source#9 | `https://files-sync9.net/drop` | 2: email:msg-ss9@vendor.example, web:https://status.vendor-ss9.example/mirror | independent (2 disjoint) | False | False | False ((0.5341, 'trusted')) |

Store: 3834 Datums (295 from untrusted sources), 4771 DERIVED_FROM edges; vector corpus 2694 documents (external docs, user messages, memories, messages). Index build: SQLite 12.2 ms, TF-IDF 1180.7 ms (not in per-query latency). Custody latency is a full Guard check (integrity + confidentiality + binding, embedded FalkorDB, decisions not recorded).
