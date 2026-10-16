# Deployment

Custody deploys as a single container that serves the API, the console and this documentation from one origin.

## The Docker image

The [`Dockerfile`](repo:Dockerfile) has two stages: Node 22 builds the console (including these docs) into `frontend/dist`, then a Python 3.12 image installs Custody with the `warden` extra and `falkordblite`, copies the build, and sets `CUSTODY_STATIC_DIR=/app/frontend/dist`. It runs as a non-root user and listens on `$PORT` (default 8000). The image's Docker `HEALTHCHECK` calls `http://127.0.0.1:8000/api/health`, so it only reports healthy when `PORT` is 8000; hosts that run their own health check against `/api/health` (such as Render) are unaffected.

```bash title="Terminal"
docker build -t custody .
docker run -p 8000:8000 \
  -e CUSTODY_FALKORDB_HOST=<host> -e CUSTODY_FALKORDB_PORT=<port> \
  -e CUSTODY_FALKORDB_USERNAME=<user> -e CUSTODY_FALKORDB_PASSWORD=<password> \
  custody
```

Or with an embedded database and no external FalkorDB:

```bash title="Terminal"
docker run -p 8000:8000 -e CUSTODY_FALKORDB_EMBEDDED_PATH=/tmp/custody.db custody
```

Locally, `docker compose --profile app up --build` starts the image next to a FalkorDB container (the `custody` service is in the `app` profile; `docker compose up -d falkordb` starts only the database). The compose file passes `ANTHROPIC_API_KEY` through from your shell if it is set.

`GET /health` (or `/api/health`) returns `status` (`ok` or `degraded`), `falkordb` (whether the database answers a ping), `version` and `public_demo`, plus `demo_tenant` in public-demo mode.

| Path                                         | Served by                                             |
| -------------------------------------------- | ----------------------------------------------------- |
| `/`, `/demo`, `/guard/…`, …                  | the console (single-page app)                         |
| `/docs`, `/docs/<page>`                      | this documentation, part of the same build            |
| `/assets/…`                                  | hashed JavaScript, CSS and screenshots from the build |
| `/api/…` (and the same paths without `/api`) | the HTTP API                                          |
| `/swagger`, `/redoc`, `/openapi.json`        | FastAPI's API reference (off in public-demo mode)     |

Any other path that is not a file in the build returns `index.html`, so deep links such as `/docs/guard#checks` or `/guard/act_…` load directly.

## Render

The image runs on Render (and Railway, Fly.io or Cloud Run) without changes. For a free, self-contained public demo on Render:

1. **New → Web Service**, connect the GitHub repository, and choose the **Docker** runtime (Render detects the Dockerfile). Leave the build context as `.` and the Dockerfile path as `./Dockerfile`.
2. Add environment variables:

   | Key                              | Value             |
   | -------------------------------- | ----------------- |
   | `CUSTODY_PUBLIC_DEMO`            | `true`            |
   | `CUSTODY_FALKORDB_EMBEDDED_PATH` | `/tmp/custody.db` |

3. Set the **Health Check Path** to `/api/health`.
4. Leave **Auto-Deploy** on: every push to the deployed branch rebuilds the image, docs included.

On startup, public-demo mode seeds the primary demo and the three worlds if the demo tenant has no recorded demo run, so an ephemeral `/tmp` database is fine. On Render's free instance type the service sleeps after a period without traffic and the first request after that takes longer while it starts.

> [!NOTE]
> Use FalkorDB Cloud (or another server) instead of the embedded database when the data must survive restarts or be shared with other processes, such as a separately hosted MCP server.

## Public-demo mode

`CUSTODY_PUBLIC_DEMO=true` lets you share a read-only deployment without building an authentication system ([`custody/api/public_demo.py`](repo:custody/api/public_demo.py)):

- **One synthetic tenant** (`CUSTODY_DEMO_TENANT`, default `acme`), seeded at startup with the primary demo and the three worlds. Every other tenant path returns 404.
- **Read-only.** Only `GET`, `HEAD` and `OPTIONS`, plus `POST …/console/demo/reset`. Recorder writes, Guard check, approve, reject, endorse and trust revocation, running scenarios or building the worlds, the Warden (which could call a paid model API) and sending disclosures all return 403. The console hides or disables those controls and shows a "Public demo · read-only" tag.
- **Reset Demo** restores the initial state deterministically (counter-based ids and a fixed simulated clock, so the graph is identical after every reset) and is rate-limited: one reset per `CUSTODY_DEMO_RESET_MIN_INTERVAL_S` (10 s), 429 with a `Retry-After` header otherwise.
- **No configuration exposed.** `/swagger`, `/redoc` and `/openapi.json` are off; `/health` returns only the status, whether FalkorDB answers, the version, the public-demo flag and the demo tenant.
- **No real credentials in the data.** The vault and its keys are simulated fakes, and raw secret values never reach the graph or any API response.

![The dashboard in public-demo mode](public-demo-dashboard.webp "Public-demo mode: the read-only tag and Reset Demo in the banner; the demo is already recorded.")

> [!LIMITATION]
> Public-demo mode is not authentication or abuse protection. There is no per-client rate limiting beyond the reset limiter, read endpoints still run real graph queries (bounded by server-side timeouts), and anyone can reset the demo for everyone. Run it on its own database, never on one that holds real tenants, and don't set `ANTHROPIC_API_KEY` or database credentials you would mind losing control of.

## Normal mode

Outside public-demo mode the console and the API have no authentication: anyone who can reach them can record data, run scenarios and approve actions as any name. The Recorder endpoints `POST …/record/approval` and `PATCH …/actions/{id}/status` also write approvals and action statuses directly, without the Guard's approval guardrails (human-only approvers, no approval for a lethal trifecta or an `INDETERMINATE` check); they are meant for a trusted integrator only. Put the deployment behind your own authentication proxy before exposing it, and do not expose those two endpoints to agents. Approvers are assumed to be humans authenticated outside Custody.

## Split hosting

To host the console separately from the API:

```bash title="Terminal"
cd frontend
VITE_API_BASE=https://api.example.com/api npm run build    # upload frontend/dist to any static host
```

Configure the static host to fall back to `index.html` for unknown paths (needed for `/docs/…` and console deep links), and set `CUSTODY_CORS_ORIGINS=https://console.example.com` on the API.

## Shipping documentation changes

The docs are Markdown files in [`frontend/src/docs/content/`](repo:frontend/src/docs/content/) with screenshots in `frontend/src/docs/images/`, compiled into the console bundle. Any deployment that builds the image (on Render, any push to the deployed branch) publishes them; there is no separate docs service.
