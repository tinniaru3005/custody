# Troubleshooting

Common errors, what causes them, and how to fix them. Messages are quoted as Custody prints them.

## Setup

### Embedded FalkorDB fails to start

```text
*** FATAL CONFIG FILE ERROR (Redis …) ***
>>> 'dir '.data''
No such file or directory
redislite.client.RedisLiteException: The binary redis-server failed to start
```

The folder for `CUSTODY_FALKORDB_EMBEDDED_PATH` does not exist. Create it (`mkdir -p .data`) and start again. The make targets do this for you.

### "CUSTODY_FALKORDB_EMBEDDED_PATH is set but falkordblite is not installed"

The embedded database needs the `falkordblite` package, which requires **Python 3.12 or newer**. Recreate the virtual environment with Python 3.12+ and install `.[dev]` (or `pip install falkordblite`), or unset the variable and use a FalkorDB server instead.

### The API does not start: "Error 111 connecting to localhost:6379. Connection refused"

Custody connects to FalkorDB at startup, and the process exits if it cannot. Start the database (`docker compose up -d falkordb`), check `CUSTODY_FALKORDB_HOST`, `_PORT`, `_USERNAME`, `_PASSWORD` and `_SSL` (or `CUSTODY_FALKORDB_URL`), or use the embedded database.

### Health reports degraded

```json
{"status": "degraded", "falkordb": false, …}
```

The API started but FalkorDB stopped answering afterwards. The console's sidebar shows "FalkorDB unreachable". Bring the database back. If the health check still reports degraded once it is answering, restart the API.

### Settings in `.env` are ignored for the Warden model or demo mode

`ANTHROPIC_API_KEY`, `CUSTODY_WARDEN_MODEL`, `CUSTODY_DEMO_MODE` and `CUSTODY_DEMO_LLM_MODEL` are read from the process environment, not from `.env`. Export them in the shell, the container or the host's settings. The other `CUSTODY_*` settings are read from both. See [Configuration](/docs/configuration#models-and-demo-mode).

### The console loads but every panel errors (Vite dev server)

`npm run dev` proxies `/api` to `http://127.0.0.1:8000`. Start the API on port 8000, or point the proxy elsewhere with `CUSTODY_API_URL=http://host:port npm run dev`.

### `/docs` shows JSON or a 404 instead of this site

`/docs` is part of the built console. Build it (`cd frontend && npm run build`) and start the API with `CUSTODY_STATIC_DIR=frontend/dist`, or use the Vite dev server. FastAPI's interactive API reference moved to `/swagger`.

## API responses

### 400 "invalid tenant …: use 1-63 chars of lowercase letters, digits, '-' or '_'"

Tenant slugs must match `[a-z0-9][a-z0-9_-]{0,62}`. Uppercase letters, dots and spaces are rejected.

### 403 "public demo is read-only; use Reset Demo to restore the initial state"

The deployment runs with `CUSTODY_PUBLIC_DEMO=true`, which refuses every write except the demo reset. Run Custody locally (or without that variable, behind your own authentication) to record data, run scenarios, approve or use the Warden.

### 403 "action … was blocked as a lethal trifecta; it has no approval option"

Working as intended: a lethal trifecta (untrusted destination, secret payload, external sink) can never be approved. The agent has to propose a different action, for example with a destination the user supplied.

### 403 "only a human approver can approve or endorse"

The approver was empty, started with `system:`, or was not of kind `human`. Pass a person's identifier as `approver`.

### 409 when recording a recall

The memory is quarantined. Quarantined memories cannot be recalled; that is how quarantine stops future spread. Forensic reads use `allow_quarantined=True` in Python.

### 429 "demo was just reset; retry in …s"

Public-demo resets are rate-limited to one per `CUSTODY_DEMO_RESET_MIN_INTERVAL_S` (10 s by default). Wait for the time in the `Retry-After` header.

### 503 "provenance search incomplete; cannot say whether a path exists"

From `GET …/data/{id}/path-to/{target}`: the complete search hit a limit, so Custody will not claim there is no path. Setting `max_depth` only helps if a path exists within that depth; a search that stops at the depth bound is still incomplete. See the next entry for the limits.

### 500 when running the Warden with planner `anthropic`

The Claude planner was requested without `ANTHROPIC_API_KEY` in the process environment, so the first planning call fails. The operator's request has already been recorded by then, so a partial investigation record stays in the graph. Set the key, or use planner `auto` (which falls back to the offline playbook) or `playbook`.

## Guard results

### A check is INDETERMINATE, or an action is held with no approval option

A complete provenance search hit its node limit (100 000), its time limit (2 000 ms) or a query error, so the Guard failed closed. Re-check once the graph is less busy; for very large tenants, raise `search_max_nodes` or `search_timeout_ms` in the tenant's `GuardPolicy` ([Configuration](/docs/configuration#guard-policy)). A later check that completes decides normally.

### A value the user typed is treated as untrusted

The argument was recorded as a model output derived from a context that included untrusted content, and no trusted Datum supplied the exact same value. The Python runtime applies exact-value attribution to tool arguments; over HTTP, pass the user-input Datum itself as the argument when the value is verbatim. See [Recording your own agents](/docs/integrating#4-a-clean-action).

### Every secret payload needs approval in my tenant

Tenants without a registered `GuardPolicy` use the default policy, in which every sink is external. Register a policy with your internal domains, hosts, Slack workspaces and ticket systems ([Configuration](/docs/configuration#guard-policy)).

### The certificate says DOWNGRADED

A model output in the destination's ancestry was recorded with `coverage: "REDUCED"` (or without a coverage value). The verdict is unaffected; the certificate's negative claim just is not exhaustive. Record outputs with their full context window.

## Tests and tooling

### `test_bench_smoke` fails with "No module named 'matplotlib'"

The benchmark report renders figures with matplotlib, which is not in any extra. `pip install matplotlib`.

### Playwright cannot find a browser

Run `npx playwright install chromium`, or set `PW_CHROMIUM=/path/to/chrome`. Playwright starts the API itself with `PYTHON` (default `.venv/bin/python`).

## Hosting

### The first request after a while is slow

Free instance types on hosts such as Render stop the service after a period without traffic; the next request waits while it starts. With an embedded database in `/tmp`, public-demo mode re-seeds the demo on that start.

### A deep link returns `{"detail":"not found"}`

The path starts with an API root (`tenants`, `health`, `swagger`, `redoc`, `openapi.json`), so the single-page-app fallback does not apply. Console and docs routes never start with these.
