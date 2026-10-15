# Scaling benchmark (generated 2026-10-06T10:47:01+00:00)

`python -m bench.run_scaling` · 7 repetitions per point (median, p95) · embedded falkordblite, Python 3.13.16, Intel(R) Xeon(R) Processor @ 2.10GHz ×2

Guard = one full `Guard.check` (evidence queries + complete searches + binding). Search = the integrity verdict's search: `bfs` (complete search) or `bounded_paths` (the evidence query already returned a violating path, which is the witness). Evidence = the depth-bounded path query (timeout 250 ms). Old@25 = what the pre-fix `*0..25` query concluded (None = it timed out after 5 s). CTE = recursive SQL over the same graph in SQLite (in-process, in-memory).

| scenario | params | variant | datums | outcome | correct | Guard median / p95 | search median (method) | queries | nodes visited | evidence median | CTE median | Old@25 |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| chain | [10] | dangerous | 12 | PATH_FOUND | yes | 11.951 / 17.777 ms | 1.196 ms (bounded_paths) | 1 | 0 | 1.196 ms | 0.019 ms | True |
| chain | [10] | clean | 12 | NO_PATH | yes | 15.118 / 22.926 ms | 5.705 ms (bfs) | 12 | 11 | 0.605 ms | 0.016 ms | False |
| chain | [25] | dangerous | 27 | PATH_FOUND | yes | 28.576 / 72.552 ms | 2.997 ms (bounded_paths) | 1 | 0 | 2.997 ms | 0.048 ms | True |
| chain | [25] | clean | 27 | NO_PATH | yes | 37.148 / 44.184 ms | 14.414 ms (bfs) | 27 | 26 | 0.803 ms | 0.032 ms | False |
| chain | [26] | dangerous | 28 | PATH_FOUND | yes | 44.794 / 51.741 ms | 15.376 ms (bfs) | 27 | 27 | 0.799 ms | 0.039 ms | False |
| chain | [26] | clean | 28 | NO_PATH | yes | 30.968 / 34.631 ms | 14.901 ms (bfs) | 28 | 27 | 0.699 ms | 0.032 ms | False |
| chain | [50] | dangerous | 52 | PATH_FOUND | yes | 76.687 / 78.64 ms | 36.737 ms (bfs) | 51 | 51 | 0.882 ms | 0.077 ms | False |
| chain | [50] | clean | 52 | NO_PATH | yes | 57.859 / 63.957 ms | 29.354 ms (bfs) | 52 | 51 | 0.813 ms | 0.062 ms | False |
| chain | [100] | dangerous | 102 | PATH_FOUND | yes | 106.354 / 133.109 ms | 49.045 ms (bfs) | 101 | 101 | 0.718 ms | 0.127 ms | False |
| chain | [100] | clean | 102 | NO_PATH | yes | 88.727 / 105.86 ms | 46.032 ms (bfs) | 102 | 101 | 0.739 ms | 0.137 ms | False |
| chain | [200] | dangerous | 202 | PATH_FOUND | yes | 244.438 / 285.086 ms | 116.749 ms (bfs) | 201 | 201 | 0.825 ms | 0.397 ms | False |
| chain | [200] | clean | 202 | NO_PATH | yes | 178.628 / 188.809 ms | 97.672 ms (bfs) | 202 | 201 | 0.758 ms | 0.349 ms | False |
| chain | [500] | dangerous | 502 | PATH_FOUND | yes | 574.746 / 706.191 ms | 282.361 ms (bfs) | 501 | 501 | 0.842 ms | 1.093 ms | False |
| chain | [500] | clean | 502 | NO_PATH | yes | 608.704 / 672.203 ms | 321.672 ms (bfs) | 502 | 501 | 0.878 ms | 0.882 ms | False |
| fan_in | [10] | dangerous | 14 | PATH_FOUND | yes | 9.806 / 15.833 ms | 0.918 ms (bounded_paths) | 1 | 0 | 0.918 ms | 0.021 ms | True |
| fan_in | [10] | clean | 14 | NO_PATH | yes | 11.169 / 15.708 ms | 3.284 ms (bfs) | 5 | 13 | 0.603 ms | 0.021 ms | False |
| fan_in | [50] | dangerous | 54 | PATH_FOUND | yes | 11.844 / 19.344 ms | 1.1 ms (bounded_paths) | 1 | 0 | 1.1 ms | 0.079 ms | True |
| fan_in | [50] | clean | 54 | NO_PATH | yes | 16.464 / 21.163 ms | 5.318 ms (bfs) | 5 | 53 | 0.807 ms | 0.057 ms | False |
| fan_in | [100] | dangerous | 104 | PATH_FOUND | yes | 14.453 / 20.729 ms | 1.384 ms (bounded_paths) | 1 | 0 | 1.384 ms | 0.108 ms | True |
| fan_in | [100] | clean | 104 | NO_PATH | yes | 19.926 / 25.157 ms | 7.462 ms (bfs) | 5 | 103 | 0.971 ms | 0.118 ms | False |
| fan_in | [500] | dangerous | 504 | PATH_FOUND | yes | 58.779 / 82.107 ms | 3.816 ms (bounded_paths) | 1 | 0 | 3.816 ms | 0.943 ms | True |
| fan_in | [500] | clean | 504 | NO_PATH | yes | 73.453 / 110.08 ms | 31.713 ms (bfs) | 5 | 503 | 3.503 ms | 1.048 ms | False |
| summary_tree | [10, 2] | dangerous | 115 | PATH_FOUND | yes | 18.672 / 22.945 ms | 1.9 ms (bounded_paths) | 1 | 0 | 1.9 ms | 0.161 ms | True |
| summary_tree | [10, 2] | clean | 115 | NO_PATH | yes | 24.336 / 33.945 ms | 8.907 ms (bfs) | 7 | 114 | 1.195 ms | 0.137 ms | False |
| summary_tree | [20, 2] | dangerous | 425 | PATH_FOUND | yes | 48.678 / 65.918 ms | 3.432 ms (bounded_paths) | 1 | 0 | 3.432 ms | 0.804 ms | True |
| summary_tree | [20, 2] | clean | 425 | NO_PATH | yes | 76.631 / 89.243 ms | 33.47 ms (bfs) | 7 | 424 | 3.428 ms | 0.66 ms | False |
| summary_tree | [5, 4] | dangerous | 785 | PATH_FOUND | yes | 86.871 / 93.459 ms | 4.889 ms (bounded_paths) | 1 | 0 | 4.889 ms | 1.729 ms | True |
| summary_tree | [5, 4] | clean | 785 | NO_PATH | yes | 140.378 / 145.044 ms | 61.4 ms (bfs) | 10 | 784 | 6.031 ms | 1.665 ms | False |
| summary_tree | [10, 3] | dangerous | 1115 | PATH_FOUND | yes | 168.611 / 188.726 ms | 6.682 ms (bounded_paths) | 1 | 0 | 6.682 ms | 2.576 ms | True |
| summary_tree | [10, 3] | clean | 1115 | NO_PATH | yes | 153.536 / 196.56 ms | 65.938 ms (bfs) | 9 | 1114 | 6.779 ms | 3.191 ms | False |
| dense_session | [5] | dangerous | 8 | PATH_FOUND | yes | 30.66 / 38.195 ms | 14.813 ms (bounded_paths) | 1 | 0 | 14.813 ms | 0.027 ms | True |
| dense_session | [5] | clean | 8 | NO_PATH | yes | 12.311 / 18.924 ms | 3.206 ms (bfs) | 3 | 7 | 0.981 ms | 0.026 ms | False |
| dense_session | [10] | dangerous | 13 | PATH_FOUND | yes | 57.705 / 85.977 ms | 36.831 ms (bounded_paths) | 1 | 0 | 36.831 ms | 0.038 ms | True |
| dense_session | [10] | clean | 13 | NO_PATH | yes | 20.33 / 24.225 ms | 4.57 ms (bfs) | 3 | 12 | 8.623 ms | 0.036 ms | False |
| dense_session | [15] | dangerous | 18 | PATH_FOUND | yes | 278.539 / 282.09 ms | 2.352 ms (bfs) | 2 | 2 | 250.887 ms | 0.093 ms | True |
| dense_session | [15] | clean | 18 | NO_PATH | yes | 269.735 / 276.927 ms | 8.123 ms (bfs) | 3 | 17 | 250.941 ms | 0.066 ms | False |
| dense_session | [20] | dangerous | 23 | PATH_FOUND | yes | 300.789 / 305.632 ms | 3.24 ms (bfs) | 2 | 2 | 251.024 ms | 0.155 ms | None |
| dense_session | [20] | clean | 23 | NO_PATH | yes | 275.222 / 281.354 ms | 12.395 ms (bfs) | 3 | 22 | 250.795 ms | 0.112 ms | None |
| dense_session | [30] | dangerous | 33 | PATH_FOUND | yes | 314.309 / 321.012 ms | 2.74 ms (bfs) | 2 | 2 | 250.957 ms | 0.393 ms | None |
| dense_session | [30] | clean | 33 | NO_PATH | yes | 290.924 / 296.787 ms | 23.931 ms (bfs) | 3 | 32 | 250.801 ms | 0.228 ms | None |
