# Commands and scripts

Everything here uses the same `CUSTODY_*` settings as the API (see [Configuration](/docs/configuration)). Run from the repository root with the virtual environment active.

## `python -m custody.warden`

The Warden's command line ([`custody/warden/__main__.py`](repo:custody/warden/__main__.py)). Logs go to stderr.

### `serve`: run the MCP server

```bash title="Terminal"
python -m custody.warden serve --tenant acme [--transport stdio|streamable-http|sse] \
  [--host 127.0.0.1] [--port 8765] [--seed-demo] [--policy NAME] [--operator NAME]
```

See [MCP integration](/docs/mcp#run-the-server) for what each flag does and how to connect clients.

### `agent`: run the Warden agent

```bash title="Terminal"
python -m custody.warden agent --tenant acme --seed-demo "That vendor page was malicious. Clean it up."
```

| Flag                     | Default                           | Meaning                                                                               |
| ------------------------ | --------------------------------- | ------------------------------------------------------------------------------------- |
| `request` (positional)   | required                          | what the operator wants                                                               |
| `--tenant`               | required                          | tenant graph                                                                          |
| `--planner`              | `auto`                            | `auto` (Claude if `ANTHROPIC_API_KEY` is set, else playbook), `anthropic`, `playbook` |
| `--mcp-url`              | none                              | use a running MCP server instead of an in-process one                                 |
| `--seed-demo`            | off                               | load the Acme incident scenario if the tenant has no actions                          |
| `--policy`, `--operator` | tenant's own, `security-operator` | as for `serve`                                                                        |
| `--json`                 | off                               | print the full report as JSON                                                         |

Output with the offline playbook (ids will differ):

```text
[planner: playbook] tools: find_sources → trace_forward → rank_risky_memories → cluster_incidents → quarantine → draft_disclosure → propose_disclosure

Incident report for web:https://docs.vaultsync-backup.example/setup (incident inc_07b1c858f703):
- Contaminated: 8 derived datum(s), 2 memories, 3 recalls, 1 messages, 3 actions.
- Quarantine: quarantined (Guard ALLOW, action act_…): d_…, d_….
- Blocked by the Guard before execution: act_….
- Already executed to external sinks: act_….
APPROVAL NEEDED — nothing has been sent:
  * act_…: disclosure to it-support@northwind-msp.example (Guard REQUIRE_HUMAN_APPROVAL). …
```

### `approve`: a human approves a disclosure

```bash title="Terminal"
python -m custody.warden approve act_… --tenant acme \
  --approver priya@acme-robotics.example [--reason "…"] [--send]
```

Prints the new verdict and status; with `--send`, also sends the disclosure (to the in-memory outbox) after a fresh Guard check:

```json
{
  "action_id": "act_…",
  "decision": "ALLOW",
  "status": "approved",
  "send": {
    "sent": true,
    "verdict": "ALLOW",
    "status": "executed",
    "destination": "it-support@northwind-msp.example",
    "detail": "sent after human approval and a fresh Guard ALLOW"
  }
}
```

### `seed`: load the incident scenario

```bash title="Terminal"
python -m custody.warden seed --tenant acme [--reset]
```

Loads the Acme incident scenario if the tenant has no actions yet; `--reset` drops the tenant graph first.

## Scripts

| Script                                                                | What it does                                                                                             | Flags                                                                                                                 |
| --------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------- |
| [`scripts/attack_demo.py`](repo:scripts/attack_demo.py)               | Runs the primary demo and prints the story and the decision with its paths                               | `--embedded PATH`, `--tenant`, `--extended`, `--investigate` (run the Warden afterwards)                              |
| [`scripts/guard_demo.py`](repo:scripts/guard_demo.py)                 | One safe internal Slack post (ALLOW) and one lethal-trifecta upload (BLOCK) through the runtime          | `--embedded PATH`, `--tenant`, `--json`                                                                               |
| [`scripts/warden_demo.py`](repo:scripts/warden_demo.py)               | Builds the incident and asks the Warden to clean it up                                                   | `--tenant` (default `acme-warden-demo`), `--planner playbook\|anthropic`, `--approve` (approve and send as the human) |
| [`scripts/seed_acme.py`](repo:scripts/seed_acme.py)                   | Seeds the synthetic Acme Robotics tenant                                                                 | `--embedded PATH`, `--tenant`, `--keep` (don't drop the graph first)                                                  |
| [`scripts/record_llm_run.py`](repo:scripts/record_llm_run.py)         | Records one real model-driven run of the primary scenario as a replay fixture; needs `ANTHROPIC_API_KEY` | `--model`, `--out`                                                                                                    |
| [`scripts/export_ui_fixtures.py`](repo:scripts/export_ui_fixtures.py) | Regenerates the JSON fixtures the console's unit tests use, from real API responses                      | none; uses `CUSTODY_FALKORDB_EMBEDDED_PATH`                                                                           |

`--embedded PATH` starts an embedded FalkorDB on that file; these scripts create its folder. `python -m custody.warden` and `warden_demo.py` take the database from `CUSTODY_*` settings instead, and with `CUSTODY_FALKORDB_EMBEDDED_PATH` the folder must already exist.

## Make targets

| Target                                    | Runs                                                                      |
| ----------------------------------------- | ------------------------------------------------------------------------- |
| `make install`                            | creates `.venv`, installs `.[dev,warden,bench]`, runs `npm ci`            |
| `make api`                                | API on :8000 against the `CUSTODY_FALKORDB_*` settings, with reload       |
| `make api-embedded`                       | API on :8000 with an embedded database at `.data/custody.db`              |
| `make api-public`                         | public-demo mode on :8000 with `.data/public.db`, serving `frontend/dist` |
| `make ui`                                 | Vite dev server on :5173                                                  |
| `make demo`                               | `scripts/attack_demo.py`                                                  |
| `make build`                              | builds the console (and these docs) into `frontend/dist`                  |
| `make lint`                               | `ruff`, then ESLint, `tsc` and Prettier in `frontend/`                    |
| `make test-backend`, `make test-frontend` | `pytest -q`, `npm test`                                                   |
| `make e2e`                                | builds, then runs the Playwright suite                                    |
| `make test`                               | lint, backend, frontend and end-to-end tests                              |
| `make fixtures`                           | `scripts/export_ui_fixtures.py`                                           |
| `make bench`, `make bench-large`          | the benchmark runs; see [Benchmarks](/docs/benchmarks)                    |

## Documentation screenshots

The screenshots in these docs are captured from the running app by a Playwright spec that is skipped unless asked for:

```bash title="Terminal"
cd frontend
npm run build
E2E_GRAPH_PREFIX=custody DOCS_SCREENSHOTS=1 npx playwright test e2e/docs-screenshots.spec.ts
```

It writes WebP files to `frontend/src/docs/images/`. The spec starts its own API on port 8765. To include the public-demo banner, also run `make api-public` (port 8000) and set `DOCS_PUBLIC_URL=http://127.0.0.1:8000`.
