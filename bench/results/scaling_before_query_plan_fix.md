# Scaling benchmark — FIRST RUN, before the BFS query-plan fix (generated 2026-10-05T21:23:49+00:00)

`python -m bench.run_scaling` · 7 repetitions per point (median, p95) · embedded falkordblite, Python 3.13.16, Intel(R) Xeon(R) Processor @ 2.10GHz ×2

Guard = one full `Guard.check` (evidence queries + complete searches + binding). Search = the integrity verdict's search: `bfs` (complete search) or `bounded_paths` (the evidence query already returned a violating path, which is the witness). Evidence = the depth-bounded path query (timeout 250 ms). Old@25 = what the pre-fix `*0..25` query concluded (None = it timed out after 5 s). CTE = recursive SQL over the same graph in SQLite (in-process, in-memory).

| scenario | params | variant | datums | outcome | correct | Guard median / p95 | search median (method) | queries | nodes visited | evidence median | CTE median | Old@25 |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| chain | [10] | dangerous | 12 | PATH_FOUND | yes | 4.133 / 8.701 ms | 1.136 ms (bounded_paths) | 1 | 0 | 1.136 ms | 0.019 ms | True |
| chain | [10] | clean | 12 | NO_PATH | yes | 8.981 / 13.434 ms | 5.665 ms (bfs) | 12 | 11 | 0.573 ms | 0.016 ms | False |
| chain | [25] | dangerous | 27 | PATH_FOUND | yes | 6.628 / 7.222 ms | 2.615 ms (bounded_paths) | 1 | 0 | 2.615 ms | 0.042 ms | True |
| chain | [25] | clean | 27 | NO_PATH | yes | 20.607 / 22.213 ms | 16.764 ms (bfs) | 27 | 26 | 0.722 ms | 0.038 ms | False |
| chain | [26] | dangerous | 28 | PATH_FOUND | yes | 22.012 / 38.038 ms | 16.451 ms (bfs) | 27 | 27 | 0.779 ms | 0.038 ms | False |
| chain | [26] | clean | 28 | NO_PATH | yes | 17.577 / 22.434 ms | 14.391 ms (bfs) | 28 | 27 | 0.65 ms | 0.026 ms | False |
| chain | [50] | dangerous | 52 | PATH_FOUND | yes | 33.52 / 39.009 ms | 27.429 ms (bfs) | 51 | 51 | 0.684 ms | 0.064 ms | False |
| chain | [50] | clean | 52 | NO_PATH | yes | 37.656 / 54.822 ms | 34.308 ms (bfs) | 52 | 51 | 0.641 ms | 0.082 ms | False |
| chain | [100] | dangerous | 102 | PATH_FOUND | yes | 85.737 / 117.425 ms | 78.263 ms (bfs) | 101 | 101 | 0.69 ms | 0.159 ms | False |
| chain | [100] | clean | 102 | NO_PATH | yes | 97.118 / 107.837 ms | 93.019 ms (bfs) | 102 | 101 | 0.784 ms | 0.141 ms | False |
| chain | [200] | dangerous | 202 | PATH_FOUND | yes | 297.711 / 333.162 ms | 277.528 ms (bfs) | 201 | 201 | 0.801 ms | 0.418 ms | False |
| chain | [200] | clean | 202 | NO_PATH | yes | 234.236 / 253.111 ms | 230.337 ms (bfs) | 202 | 201 | 0.79 ms | 0.257 ms | False |
| chain | [500] | dangerous | 502 | PATH_FOUND | yes | 990.587 / 1076.971 ms | 965.884 ms (bfs) | 501 | 501 | 0.733 ms | 1.07 ms | False |
| chain | [500] | clean | 502 | NO_PATH | yes | 998.785 / 1112.44 ms | 994.702 ms (bfs) | 502 | 501 | 0.933 ms | 0.942 ms | False |
| fan_in | [10] | dangerous | 14 | PATH_FOUND | yes | 3.264 / 6.01 ms | 0.686 ms (bounded_paths) | 1 | 0 | 0.686 ms | 0.018 ms | True |
| fan_in | [10] | clean | 14 | NO_PATH | yes | 5.529 / 8.849 ms | 2.748 ms (bfs) | 5 | 13 | 0.449 ms | 0.015 ms | False |
| fan_in | [50] | dangerous | 54 | PATH_FOUND | yes | 3.591 / 6.348 ms | 0.897 ms (bounded_paths) | 1 | 0 | 0.897 ms | 0.066 ms | True |
| fan_in | [50] | clean | 54 | NO_PATH | yes | 16.282 / 20.261 ms | 11.594 ms (bfs) | 5 | 53 | 0.998 ms | 0.055 ms | False |
| fan_in | [100] | dangerous | 104 | PATH_FOUND | yes | 4.286 / 6.945 ms | 1.245 ms (bounded_paths) | 1 | 0 | 1.245 ms | 0.144 ms | True |
| fan_in | [100] | clean | 104 | NO_PATH | yes | 26.834 / 34.834 ms | 23.204 ms (bfs) | 5 | 103 | 0.889 ms | 0.137 ms | False |
| fan_in | [500] | dangerous | 504 | PATH_FOUND | yes | 6.757 / 9.564 ms | 3.055 ms (bounded_paths) | 1 | 0 | 3.055 ms | 0.96 ms | True |
| fan_in | [500] | clean | 504 | NO_PATH | yes | 571.099 / 660.596 ms | 563.947 ms (bfs) | 5 | 503 | 2.764 ms | 0.588 ms | False |
| summary_tree | [10, 2] | dangerous | 115 | PATH_FOUND | yes | 5.917 / 11.384 ms | 1.584 ms (bounded_paths) | 1 | 0 | 1.584 ms | 0.157 ms | True |
| summary_tree | [10, 2] | clean | 115 | NO_PATH | yes | 43.766 / 46.862 ms | 38.301 ms (bfs) | 7 | 114 | 1.202 ms | 0.138 ms | False |
| summary_tree | [20, 2] | dangerous | 425 | PATH_FOUND | yes | 7.858 / 12.081 ms | 3.508 ms (bounded_paths) | 1 | 0 | 3.508 ms | 0.818 ms | True |
| summary_tree | [20, 2] | clean | 425 | NO_PATH | yes | 449.054 / 483.4 ms | 441.15 ms (bfs) | 7 | 424 | 3.078 ms | 0.559 ms | False |
| summary_tree | [5, 4] | dangerous | 785 | PATH_FOUND | yes | 7.705 / 10.626 ms | 4.23 ms (bounded_paths) | 1 | 0 | 4.23 ms | 1.383 ms | True |
| summary_tree | [5, 4] | clean | 785 | NO_PATH | yes | 1431.238 / 1474.792 ms | 1420.045 ms (bfs) | 10 | 784 | 4.805 ms | 1.417 ms | False |
| summary_tree | [10, 3] | dangerous | 1115 | PATH_FOUND | yes | 8.932 / 15.883 ms | 5.641 ms (bounded_paths) | 1 | 0 | 5.641 ms | 3.094 ms | True |
| summary_tree | [10, 3] | clean | 1115 | INDETERMINATE | NO | 2011.655 / 2015.401 ms | 2000.962 ms (bfs) | 9 | 1114 | 6.201 ms | 2.038 ms | False |
| dense_session | [5] | dangerous | 8 | PATH_FOUND | yes | 15.861 / 18.546 ms | 9.9 ms (bounded_paths) | 1 | 0 | 9.9 ms | 0.017 ms | True |
| dense_session | [5] | clean | 8 | NO_PATH | yes | 9.174 / 20.09 ms | 3.553 ms (bfs) | 3 | 7 | 1.011 ms | 0.024 ms | False |
| dense_session | [10] | dangerous | 13 | PATH_FOUND | yes | 34.941 / 56.2 ms | 27.697 ms (bounded_paths) | 1 | 0 | 27.697 ms | 0.039 ms | True |
| dense_session | [10] | clean | 13 | NO_PATH | yes | 20.128 / 23.756 ms | 5.484 ms (bfs) | 3 | 12 | 9.51 ms | 0.054 ms | False |
| dense_session | [15] | dangerous | 18 | PATH_FOUND | yes | 258.482 / 338.557 ms | 2.398 ms (bfs) | 2 | 2 | 250.949 ms | 0.055 ms | True |
| dense_session | [15] | clean | 18 | NO_PATH | yes | 264.083 / 264.843 ms | 9.336 ms (bfs) | 3 | 17 | 250.839 ms | 0.071 ms | False |
| dense_session | [20] | dangerous | 23 | PATH_FOUND | yes | 258.91 / 265.73 ms | 2.827 ms (bfs) | 2 | 2 | 250.95 ms | 0.124 ms | None |
| dense_session | [20] | clean | 23 | NO_PATH | yes | 271.176 / 273.866 ms | 15.616 ms (bfs) | 3 | 22 | 251.121 ms | 0.101 ms | None |
| dense_session | [30] | dangerous | 33 | PATH_FOUND | yes | 259.392 / 269.266 ms | 3.249 ms (bfs) | 2 | 2 | 251.039 ms | 0.224 ms | None |
| dense_session | [30] | clean | 33 | NO_PATH | yes | 287.971 / 299.766 ms | 31.361 ms (bfs) | 3 | 32 | 251.086 ms | 0.216 ms | None |
