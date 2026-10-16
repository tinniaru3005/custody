# Configuration

Server settings are environment variables prefixed with `CUSTODY_`, read by [`custody/config.py`](repo:custody/config.py). They can also be put in a `.env` file in the directory the process starts in; [`.env.example`](repo:.env.example) lists them with comments.

## Database

| Variable                         | Default     | Purpose                                                                                                                            |
| -------------------------------- | ----------- | ---------------------------------------------------------------------------------------------------------------------------------- |
| `CUSTODY_FALKORDB_HOST`          | `localhost` | FalkorDB server or Cloud instance host                                                                                             |
| `CUSTODY_FALKORDB_PORT`          | `6379`      | port                                                                                                                               |
| `CUSTODY_FALKORDB_USERNAME`      | none        | FalkorDB Cloud user                                                                                                                |
| `CUSTODY_FALKORDB_PASSWORD`      | none        | FalkorDB Cloud password                                                                                                            |
| `CUSTODY_FALKORDB_SSL`           | `false`     | TLS to the server                                                                                                                  |
| `CUSTODY_FALKORDB_URL`           | none        | `redis://user:pass@host:port` or `rediss://…` (TLS); overrides host and port                                                       |
| `CUSTODY_FALKORDB_EMBEDDED_PATH` | none        | run an embedded FalkorDB (`falkordblite`, Python 3.12+) on this file; overrides all server settings. The file's folder must exist. |

## Graph

| Variable                  | Default   | Purpose                                                                                                                                                                                                                                                              |
| ------------------------- | --------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `CUSTODY_GRAPH_PREFIX`    | `custody` | graph names are `<prefix>:<tenant>`                                                                                                                                                                                                                                  |
| `CUSTODY_MAX_TRACE_DEPTH` | `25`      | maximum `DERIVED_FROM` hops in lineage, path-to and trace views, in exact-value attribution candidates and in the Warden's analyses. Guard verdicts use a complete search and do not depend on it; the Guard's evidence queries use `GuardPolicy.max_depth` instead. |

## HTTP

| Variable               | Default | Purpose                                                                                                                   |
| ---------------------- | ------- | ------------------------------------------------------------------------------------------------------------------------- |
| `CUSTODY_STATIC_DIR`   | none    | serve the built console (`frontend/dist`) at `/`, with the SPA fallback. Set to `/app/frontend/dist` in the Docker image. |
| `CUSTODY_CORS_ORIGINS` | none    | comma-separated origins, only when the console is hosted on a different origin                                            |
| `PORT`                 | `8000`  | the port the Docker image listens on (read by the image's start command, not by Custody)                                  |

## Public demo

| Variable                            | Default | Purpose                                                                         |
| ----------------------------------- | ------- | ------------------------------------------------------------------------------- |
| `CUSTODY_PUBLIC_DEMO`               | `false` | read-only public-demo mode; see [Deployment](/docs/deployment#public-demo-mode) |
| `CUSTODY_DEMO_TENANT`               | `acme`  | the only tenant reachable in public-demo mode                                   |
| `CUSTODY_DEMO_RESET_MIN_INTERVAL_S` | `10`    | minimum seconds between two demo resets                                         |

## Models and demo mode

These four are read directly from the process environment, **not** from `.env`. Export them in your shell, your container or your host's settings.

| Variable                 | Default             | Purpose                                                                                                                                                                                                                                                                                                                                                                                                                             |
| ------------------------ | ------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `ANTHROPIC_API_KEY`      | none                | lets the Warden plan with Claude (planner `auto` or `anthropic`) and enables `scripts/record_llm_run.py`. Without it the Warden uses the offline playbook.                                                                                                                                                                                                                                                                          |
| `CUSTODY_WARDEN_MODEL`   | `claude-sonnet-5-5` | model for the Claude planner                                                                                                                                                                                                                                                                                                                                                                                                        |
| `CUSTODY_DEMO_MODE`      | `auto`              | primary demo: `auto` replays `custody/demo/fixtures/llm_run.json` only if it is a real-model recording that contains a BLOCK, else runs the scripted simulation; `recorded` also replays a test-double recording (labelled as not a real model); `scripted` always runs the simulation. No real recording ships, so `auto` currently runs the scripted demo. The console's `POST …/console/demo/attack?mode=` overrides it per run. |
| `CUSTODY_DEMO_LLM_MODEL` | the Warden default  | model used by `scripts/record_llm_run.py`                                                                                                                                                                                                                                                                                                                                                                                           |

> [!WARNING]
> Don't set `ANTHROPIC_API_KEY` on a public deployment you don't want others to spend from. Public-demo mode refuses Warden runs, but a normal-mode deployment without authentication does not.

## Benchmarks

Read from the process environment by [`bench/baselines.py`](repo:bench/baselines.py) only; the server ignores them.

| Variable                  | Default             | Purpose                                                                                    |
| ------------------------- | ------------------- | ------------------------------------------------------------------------------------------ |
| `CUSTODY_BENCH_SBERT`     | `all-MiniLM-L6-v2`  | sentence-transformers model for `python -m bench.run_correctness --sbert`                  |
| `CUSTODY_BENCH_LLM_MODEL` | `claude-sonnet-4-5` | model for the LLM-judge baseline; differs from the Warden's default `CUSTODY_WARDEN_MODEL` |
| `ANTHROPIC_API_KEY`       | none                | enables the LLM-judge parts of the benchmarks                                              |

## Console build

Read at build time by Vite (`frontend/.env.local` or the environment of `npm run build`):

| Variable          | Default                 | Purpose                                                              |
| ----------------- | ----------------------- | -------------------------------------------------------------------- |
| `VITE_API_BASE`   | `/api`                  | API base URL; set to `https://api.example.com/api` for split hosting |
| `VITE_TENANT`     | `acme`                  | the tenant the console shows                                         |
| `CUSTODY_API_URL` | `http://127.0.0.1:8000` | where `npm run dev` and `npm run preview` proxy `/api`               |

## Tests

Read from the process environment by `tests/conftest.py` and [`frontend/playwright.config.ts`](repo:frontend/playwright.config.ts):

| Variable                                                   | Default                                      | Purpose                                                                                                                    |
| ---------------------------------------------------------- | -------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------- |
| `CUSTODY_TEST_FALKORDB_HOST`, `CUSTODY_TEST_FALKORDB_PORT` | none (embedded), `6379`                      | run `pytest` against a FalkorDB server instead of an embedded one                                                          |
| `PYTHON`                                                   | `.venv/bin/python`                           | Playwright: interpreter that starts the API                                                                                |
| `PW_CHROMIUM`                                              | none                                         | Playwright: path to a preinstalled Chromium                                                                                |
| `E2E_PORT`, `E2E_DB`, `E2E_GRAPH_PREFIX`                   | `8765`, `/tmp/custody-e2e.db`, `custody-e2e` | Playwright: API port, embedded database file, graph prefix (the API runs with `CUSTODY_DEMO_MODE=scripted` and no API key) |
| `DOCS_SCREENSHOTS`, `DOCS_PUBLIC_URL`, `SCREENSHOTS`       | unset (specs skipped)                        | enable the screenshot specs; see [Commands](/docs/cli#documentation-screenshots)                                           |

## Guard policy

The Guard policy decides which action types are checked and which destinations count as internal. It is configured in code, not through environment variables: [`custody/guard/policy.py`](repo:custody/guard/policy.py) defines a `GuardPolicy` per tenant. Tenants without one get `DEFAULT_POLICY`, which has no internal destinations, so **every sink is external**.

The demo tenant's policy:

```python title="custody/guard/policy.py"
ACME_POLICY = GuardPolicy(
    name="acme-robotics",
    internal_email_domains=frozenset({"acme-robotics.example"}),
    internal_slack_workspaces=frozenset({"acme-robotics"}),
    shared_slack_channels=frozenset({"#ext-rivalbots-partners"}),
    internal_hosts=frozenset({"acme-robotics.example"}),
    internal_ticket_systems=frozenset({"acme-jira"}),
)

_TENANT_POLICIES: Dict[str, GuardPolicy] = {"acme": ACME_POLICY}
```

To add your own tenant, add an entry to `_TENANT_POLICIES`, or call `register_policy` from your own startup module before serving requests:

```python title="myapp.py"
from custody.guard.policy import GuardPolicy, register_policy

register_policy("myteam", GuardPolicy(
    name="myteam",
    internal_email_domains=frozenset({"myteam.example"}),
    internal_hosts=frozenset({"internal.myteam.example"}),
))

from custody.api.app import app  # noqa: E402  (serve with: uvicorn myapp:app)
```

| `GuardPolicy` field                                                                                                         | Default              | Meaning                                                                                                                                                             |
| --------------------------------------------------------------------------------------------------------------------------- | -------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `internal_email_domains`, `internal_slack_workspaces`, `shared_slack_channels`, `internal_hosts`, `internal_ticket_systems` | empty                | what counts as internal (subdomains of internal domains and hosts are internal; channels in `shared_slack_channels` are external even inside an internal workspace) |
| `actions`                                                                                                                   | `DEFAULT_ACTIONS`    | per action type: `outbound`, `irreversible`, `risk` (`low`/`high`), `human_review`                                                                                  |
| `destination_roles`                                                                                                         | `{"destination"}`    | argument roles checked for integrity; every other role is a payload                                                                                                 |
| `max_depth`, `path_limit`, `evidence_timeout_ms`                                                                            | 25, 50, 250          | bounds of the evidence queries; they can only confirm a violation, never clear one                                                                                  |
| `search_max_depth`, `search_max_nodes`, `search_timeout_ms`                                                                 | none, 100 000, 2 000 | bounds of the complete searches; hitting one makes a check INDETERMINATE (fail closed)                                                                              |
| `precedent_escalation`                                                                                                      | `true`               | escalate to BLOCK after a human rejected a secret-bearing action to the same sink                                                                                   |
| `egress_endorsements`                                                                                                       | `true`               | allow secret-egress endorsements to clear confidentiality                                                                                                           |
| `contamination_analysis`, `contamination_timeout_ms`, `contamination_max_checks`                                            | `true`, 1 000, 25    | the untrusted-roots explanation                                                                                                                                     |

Action types in `DEFAULT_ACTIONS`:

| Action type                                                                         | Outbound | Irreversible | Risk | Human review |
| ----------------------------------------------------------------------------------- | -------- | ------------ | ---- | ------------ |
| `send_email`, `post_slack`, `upload_backup`, `http_post`, `configure_backup`        | yes      | yes          | high |              |
| `send_disclosure`                                                                   | yes      | yes          | high | **yes**      |
| `update_ticket`, `add_ticket_comment`                                               |          | yes          | low  |              |
| `quarantine_memory`, `revoke_source_trust`                                          |          | yes          | low  |              |
| `unquarantine_memory`, `endorse_data`, `restore_source_trust`, `weaken_restriction` |          | yes          | high | **yes**      |
| `read_file`, `search_memory`                                                        |          |              | low  | not checked  |
| anything else                                                                       | yes      | yes          | high |              |
