# SQL vs FalkorDB: practical comparison (generated 2026-10-06T10:49:36+00:00)

embedded falkordblite vs SQLite 3.45.1 (in-process), Python 3.13.16, Intel(R) Xeon(R) Processor @ 2.10GHz ×2; per-query cap 10 s.

## Cycle handling

| start | truth | FalkorDB BFS | SQLite reach (UNION) | SQLite path-string CTE |
|---|---|---|---|---|
| a | True | True (4.565 ms) | True (ok, 0.594 ms) | True (ok, 0.407 ms) |
| z | False | False (3.254 ms) | False (ok, 0.267 ms) | False (ok, 0.236 ms) |

## Explanation path on dense multi-turn sessions (≈2^t paths)

| turns | edges | FalkorDB BFS | FalkorDB *1..N pattern | SQLite levels CTE | SQLite path-string CTE |
|---|---|---|---|---|---|
| 6 | 21 | 3.021 ms | 1.318 ms | 0.654 ms | 0.502 ms |
| 10 | 55 | 3.224 ms | 7.251 ms | 0.764 ms | 2.161 ms |
| 14 | 105 | 4.486 ms | 104.875 ms | 0.794 ms | 22.019 ms |
| 18 | 171 | 3.253 ms | 1310.07 ms | 1.239 ms | 433.658 ms |
| 22 | 253 | 3.035 ms | 58855.468 ms **error: Timeout reading from socket** | 1.418 ms | 8257.9 ms |

## Query size

| query | lines | characters |
|---|---|---|
| sqlite_reach_union | 6 | 194 |
| sqlite_levels | 7 | 174 |
| sqlite_pathstring | 8 | 322 |
| falkordb_varlength | 1 | 173 |
| falkordb_bfs (one level query) | 3 | 178 |
| falkordb_bfs (Python driver: traversal.search) | 117 | 5337 |
