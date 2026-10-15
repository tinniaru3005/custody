# Large-graph benchmark (generated 2026-10-06T10:24:41+00:00)

`python -m bench.run_large` · embedded falkordblite, Python 3.13.16, Intel(R) Xeon(R) Processor @ 2.10GHz ×2 · search repetitions 5 (Guard checks ≤3)

Bulk of each graph written with batched Cypher in the Recorder's schema; the recall, destination and action through the Recorder. `default` = shipped limits (100k nodes, 2 s); `raised` = 2M nodes, 120 s. Search = the complete integrity search alone; Guard = full `Guard.check` (evidence query, both searches, certificate on ALLOW).

| scenario | params | variant | datums | limits | outcome (termination) | correct | nodes visited | search p50 / p95 | Guard verdict | Guard p50 | certificate | CTE p50 |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| fan_in | [1000] | dangerous | 1,005 | default | PATH_FOUND (path_found) | yes | 801 | 47.314 / 74.992 ms | REQUIRE_HUMAN_APPROVAL | 38.419 ms | — | 1.569 ms |
| fan_in | [1000] | dangerous | 1,005 | raised | PATH_FOUND (path_found) | yes | 801 | 55.974 / 67.699 ms | REQUIRE_HUMAN_APPROVAL | 34.745 ms | — | 1.569 ms |
| fan_in | [1000] | clean | 1,005 | default | NO_PATH (exhausted) | yes | 1,004 | 52.372 / 66.253 ms | ALLOW | 109.3 ms | yes | 1.38 ms |
| fan_in | [1000] | clean | 1,005 | raised | NO_PATH (exhausted) | yes | 1,004 | 50.99 / 53.118 ms | ALLOW | 121.591 ms | yes | 1.38 ms |
| fan_in | [10000] | dangerous | 10,005 | default | PATH_FOUND (path_found) | yes | 9,473 | 547.861 / 673.014 ms | REQUIRE_HUMAN_APPROVAL | 326.453 ms | — | 23.019 ms |
| fan_in | [10000] | dangerous | 10,005 | raised | PATH_FOUND (path_found) | yes | 9,473 | 497.422 / 586.179 ms | REQUIRE_HUMAN_APPROVAL | 297.508 ms | — | 23.019 ms |
| fan_in | [10000] | clean | 10,005 | default | NO_PATH (exhausted) | yes | 10,004 | 541.465 / 573.269 ms | ALLOW | 1,321.493 ms | yes | 25.895 ms |
| fan_in | [10000] | clean | 10,005 | raised | NO_PATH (exhausted) | yes | 10,004 | 558.067 / 638.338 ms | ALLOW | 1,312.427 ms | yes | 25.895 ms |
| fan_in | [100000] | dangerous | 100,005 | default | INDETERMINATE (timeout) | n/a (incomplete) | 4 | 2,008.131 / 2,010.402 ms | REQUIRE_HUMAN_APPROVAL | 2,280.924 ms | — | 241.607 ms |
| fan_in | [100000] | dangerous | 100,005 | raised | PATH_FOUND (path_found) | yes | 12,248 | 5,423.801 / 5,792.977 ms | REQUIRE_HUMAN_APPROVAL | 9,034.015 ms | — | 241.607 ms |
| fan_in | [100000] | clean | 100,005 | default | INDETERMINATE (timeout) | n/a (incomplete) | 4 | 2,014.919 / 2,016.043 ms | REQUIRE_HUMAN_APPROVAL | 2,279.195 ms | — | 292.177 ms |
| fan_in | [100000] | clean | 100,005 | raised | NO_PATH (exhausted) | yes | 100,004 | 5,754.127 / 5,837.521 ms | ALLOW | 14,363.185 ms | yes | 292.177 ms |
| summary_tree | [10, 3] | dangerous | 1,115 | default | PATH_FOUND (path_found) | yes | 911 | 57.494 / 62.202 ms | REQUIRE_HUMAN_APPROVAL | 47.14 ms | — | 2.19 ms |
| summary_tree | [10, 3] | dangerous | 1,115 | raised | PATH_FOUND (path_found) | yes | 911 | 59.245 / 62.647 ms | REQUIRE_HUMAN_APPROVAL | 46.865 ms | — | 2.19 ms |
| summary_tree | [10, 3] | clean | 1,115 | default | NO_PATH (exhausted) | yes | 1,114 | 62.187 / 141.509 ms | ALLOW | 139.422 ms | yes | 1.304 ms |
| summary_tree | [10, 3] | clean | 1,115 | raised | NO_PATH (exhausted) | yes | 1,114 | 79.258 / 89.591 ms | ALLOW | 100.307 ms | yes | 1.304 ms |
| summary_tree | [10, 4] | dangerous | 11,115 | default | PATH_FOUND (path_found) | yes | 10,583 | 745.358 / 909.923 ms | REQUIRE_HUMAN_APPROVAL | 357.178 ms | — | 25.75 ms |
| summary_tree | [10, 4] | dangerous | 11,115 | raised | PATH_FOUND (path_found) | yes | 10,583 | 588.135 / 624.598 ms | REQUIRE_HUMAN_APPROVAL | 373.632 ms | — | 25.75 ms |
| summary_tree | [10, 4] | clean | 11,115 | default | NO_PATH (exhausted) | yes | 11,114 | 411.79 / 760.509 ms | ALLOW | 1,327.672 ms | yes | 33.809 ms |
| summary_tree | [10, 4] | clean | 11,115 | raised | NO_PATH (exhausted) | yes | 11,114 | 619.824 / 724.118 ms | ALLOW | 1,435.569 ms | yes | 33.809 ms |
| summary_tree | [10, 5] | dangerous | 111,115 | default | PATH_FOUND (path_found) | yes | 23,358 | 1,390.77 / 1,442.312 ms | REQUIRE_HUMAN_APPROVAL | 2,962.511 ms | — | 341.593 ms |
| summary_tree | [10, 5] | dangerous | 111,115 | raised | PATH_FOUND (path_found) | yes | 23,358 | 1,374.396 / 1,475.461 ms | REQUIRE_HUMAN_APPROVAL | 2,842.642 ms | — | 341.593 ms |
| summary_tree | [10, 5] | clean | 111,115 | default | INDETERMINATE (timeout) | n/a (incomplete) | 41,114 | 2,033.773 / 2,090.14 ms | REQUIRE_HUMAN_APPROVAL | 2,266.064 ms | — | 301.643 ms |
| summary_tree | [10, 5] | clean | 111,115 | raised | NO_PATH (exhausted) | yes | 111,114 | 6,000.064 / 6,317.066 ms | ALLOW | 14,252.896 ms | yes | 301.643 ms |
| summary_tree | [50, 3] | dangerous | 127,555 | default | INDETERMINATE (timeout) | n/a (incomplete) | 27,554 | 2,010.369 / 2,011.867 ms | REQUIRE_HUMAN_APPROVAL | 2,269.452 ms | — | 348.779 ms |
| summary_tree | [50, 3] | dangerous | 127,555 | raised | PATH_FOUND (path_found) | yes | 115,095 | 7,254.119 / 7,832.857 ms | REQUIRE_HUMAN_APPROVAL | 9,286.111 ms | — | 348.779 ms |
| summary_tree | [50, 3] | clean | 127,555 | default | INDETERMINATE (timeout) | n/a (incomplete) | 52,554 | 2,335.551 / 2,467.585 ms | REQUIRE_HUMAN_APPROVAL | 2,630.724 ms | — | 365.746 ms |
| summary_tree | [50, 3] | clean | 127,555 | raised | NO_PATH (exhausted) | yes | 127,554 | 7,152.721 / 7,444.868 ms | ALLOW | 16,943.49 ms | yes | 365.746 ms |
| chain_in_100k | [100, 100000] | dangerous | 100,105 | default | PATH_FOUND (path_found) | yes | 104 | 91.784 / 99.446 ms | REQUIRE_HUMAN_APPROVAL | 338.116 ms | — | 4.857 ms |
| chain_in_100k | [100, 100000] | dangerous | 100,105 | raised | PATH_FOUND (path_found) | yes | 104 | 84.094 / 98.757 ms | REQUIRE_HUMAN_APPROVAL | 278.259 ms | — | 4.857 ms |
| chain_in_100k | [100, 100000] | clean | 100,105 | default | NO_PATH (exhausted) | yes | 104 | 86.636 / 92.013 ms | ALLOW | 139.315 ms | yes | 2.858 ms |
| chain_in_100k | [100, 100000] | clean | 100,105 | raised | NO_PATH (exhausted) | yes | 104 | 76.28 / 94.777 ms | ALLOW | 165.242 ms | yes | 2.858 ms |
| chain_in_100k | [1000, 100000] | dangerous | 101,005 | default | PATH_FOUND (path_found) | yes | 1,004 | 640.98 / 778.084 ms | REQUIRE_HUMAN_APPROVAL | 2,313.286 ms | — | 7.972 ms |
| chain_in_100k | [1000, 100000] | dangerous | 101,005 | raised | PATH_FOUND (path_found) | yes | 1,004 | 710.628 / 755.151 ms | REQUIRE_HUMAN_APPROVAL | 2,061.668 ms | — | 7.972 ms |
| chain_in_100k | [1000, 100000] | clean | 101,005 | default | NO_PATH (exhausted) | yes | 1,004 | 937.655 / 945.366 ms | ALLOW | 1,521.609 ms | yes | 6.169 ms |
| chain_in_100k | [1000, 100000] | clean | 101,005 | raised | NO_PATH (exhausted) | yes | 1,004 | 817.959 / 898.228 ms | ALLOW | 1,498.311 ms | yes | 6.169 ms |
| chain_in_100k | [3000, 100000] | dangerous | 103,005 | default | INDETERMINATE (timeout) | n/a (incomplete) | 2,542 | 1,999.672 / 1,999.788 ms | REQUIRE_HUMAN_APPROVAL | 2,012.377 ms | — | 9.914 ms |
| chain_in_100k | [3000, 100000] | dangerous | 103,005 | raised | PATH_FOUND (path_found) | yes | 3,004 | 2,655.564 / 2,797.652 ms | REQUIRE_HUMAN_APPROVAL | 5,245.081 ms | — | 9.914 ms |
| chain_in_100k | [3000, 100000] | clean | 103,005 | default | INDETERMINATE (timeout) | n/a (incomplete) | 2,241 | 1,999.792 / 1,999.943 ms | REQUIRE_HUMAN_APPROVAL | 2,007.591 ms | — | 18.723 ms |
| chain_in_100k | [3000, 100000] | clean | 103,005 | raised | NO_PATH (exhausted) | yes | 3,004 | 2,516.07 / 2,544.609 ms | ALLOW | 4,777.642 ms | yes | 18.723 ms |
