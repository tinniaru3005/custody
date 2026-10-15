# Installation

Set up a development environment: the Python backend, the React console, and one of three FalkorDB options.

## Requirements

| Component | Version                        | Notes                                                        |
| --------- | ------------------------------ | ------------------------------------------------------------ |
| Python    | 3.10 or newer                  | **3.12 or newer** for the embedded FalkorDB (`falkordblite`) |
| Node.js   | 20.19+ or 22.12+               | required by Vite 8; the Docker image uses Node 22            |
| FalkorDB  | any of the three options below | a local server (Docker), FalkorDB Cloud, or embedded         |

## Install the backend

```bash title="Terminal"
git clone https://github.com/tinniaru3005/custody.git
cd custody
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev,warden]"
```

The package defines these optional extras in [`pyproject.toml`](repo:pyproject.toml):

| Extra    | Installs                                                             | Needed for                                                 |
| -------- | -------------------------------------------------------------------- | ---------------------------------------------------------- |
| `warden` | `mcp` (MCP Python SDK v2), `anthropic`                               | the Warden MCP server and agent, the console's Warden page |
| `dev`    | `pytest`, `ruff`, `httpx`, `mcp`, and `falkordblite` on Python 3.12+ | tests, linting, the embedded database                      |
| `bench`  | `scikit-learn`                                                       | the benchmark baselines in `bench/`                        |

`make install` creates `.venv` and installs all three extras, then runs `npm ci` in `frontend/`.

## Install the console

```bash title="Terminal"
cd frontend
npm ci
cd ..
```

## Choose a database

Every tenant gets its own graph, named `<prefix>:<tenant>` (for example `custody:acme`). Pick one way to run FalkorDB:

### A: local FalkorDB server (Docker)

```bash title="Terminal"
docker compose up -d falkordb
```

This publishes FalkorDB on port 6379 and its browser UI on port 3000. The defaults (`localhost:6379`) need no configuration.

### B: embedded FalkorDB (no Docker)

Requires Python 3.12+ and the `dev` extra (or `pip install falkordblite`). Point Custody at a database file; its folder must exist:

```bash title="Terminal"
mkdir -p .data
export CUSTODY_FALKORDB_EMBEDDED_PATH=.data/custody.db
```

`falkordblite` starts a private FalkorDB process for that file. This is what the test suite, the Playwright end-to-end tests and the hosted public demo use.

### C: FalkorDB Cloud

Copy the example settings file and fill in the host, port, username and password from your instance page:

```bash title="Terminal"
cp .env.example .env
```

```ini title=".env"
CUSTODY_FALKORDB_HOST=r-xxxxxxxx.instance-xxxx.falkordb.cloud
CUSTODY_FALKORDB_PORT=6379
CUSTODY_FALKORDB_USERNAME=falkordb
CUSTODY_FALKORDB_PASSWORD=change-me
CUSTODY_FALKORDB_SSL=false
# or one URL instead (rediss:// for TLS); a URL wins over host/port:
# CUSTODY_FALKORDB_URL=redis://falkordb:change-me@r-xxxxxxxx.falkordb.cloud:6379
```

Settings are read from environment variables and from a `.env` file in the directory you start the process from. If both `CUSTODY_FALKORDB_EMBEDDED_PATH` and server settings are present, the embedded database wins. See [Configuration](/docs/configuration) for every variable.

## Run it

**Two processes** (recommended while developing the console):

```bash title="Terminal 1: API on :8000"
uvicorn custody.api.app:app --reload --port 8000
```

```bash title="Terminal 2: console on :5173"
cd frontend && npm run dev
```

The Vite dev server proxies `/api` to `http://127.0.0.1:8000` (override with `CUSTODY_API_URL`). Open [http://localhost:5173](http://localhost:5173).

**One process** serving the built console, as in production:

```bash title="Terminal"
cd frontend && npm run build && cd ..
CUSTODY_STATIC_DIR=frontend/dist uvicorn custody.api.app:app --port 8000
```

Open [http://localhost:8000](http://localhost:8000). The console is at `/`, these docs at `/docs`, the HTTP API under `/api`, and FastAPI's interactive API reference at `/swagger` (with `/redoc` and `/openapi.json`).

The make targets wrap the same commands:

| Target              | Runs                                                                                                            |
| ------------------- | --------------------------------------------------------------------------------------------------------------- |
| `make api`          | API on :8000 against the `CUSTODY_FALKORDB_*` settings, with reload                                             |
| `make api-embedded` | API on :8000 with an embedded database at `.data/custody.db`                                                    |
| `make api-public`   | API on :8000 in [public-demo mode](/docs/deployment#public-demo-mode), serving `frontend/dist` (build it first) |
| `make ui`           | Vite dev server on :5173                                                                                        |
| `make build`        | `npm run build` in `frontend/`                                                                                  |

## Verify the setup

```bash title="Terminal"
curl -s http://localhost:8000/api/health
```

```json
{ "status": "ok", "falkordb": true, "version": "0.1.0", "public_demo": false }
```

`"status":"degraded"` with `"falkordb":false` means the API is up but cannot reach FalkorDB; see [Troubleshooting](/docs/troubleshooting#health-reports-degraded).

To run the test suites:

```bash title="Terminal"
pytest                                    # backend (embedded FalkorDB, or CUSTODY_TEST_FALKORDB_HOST=localhost)
ruff check custody tests scripts bench

cd frontend
npm test                                  # Vitest + Testing Library
npm run lint && npm run typecheck && npm run format:check
npm run build && npx playwright test      # end-to-end: real backend + built UI + Chromium
```

Playwright starts the API itself with an embedded database. Set `PYTHON=` if your virtual environment is not at `.venv`, and `PW_CHROMIUM=/path/to/chrome` to use an installed browser instead of `npx playwright install chromium`.

> [!NOTE]
> `tests/unit/test_bench_smoke.py` also renders the benchmark figures, which needs `matplotlib`. It is not in any extra, so install it separately (`pip install matplotlib`) if you run the full suite.
