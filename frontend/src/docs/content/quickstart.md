# Quickstart

Run the API, the web console and the attack demo on your machine in a few minutes. You need either Docker, or Python 3.12+ and Node.js 20.19+ (or 22.12+).

## Option A: Docker

From the repository root, this builds one image with the API and the console and starts it next to a FalkorDB server:

```bash title="Terminal"
git clone https://github.com/tinniaru3005/custody.git
cd custody
docker compose --profile app up --build
```

Open [http://localhost:8000](http://localhost:8000). The FalkorDB browser UI is also published on port 3000.

## Option B: Python and Node, no Docker

This uses an embedded FalkorDB (the `falkordblite` package), which needs **Python 3.12 or newer**.

```bash title="Terminal"
git clone https://github.com/tinniaru3005/custody.git
cd custody

python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev,warden]"            # dev includes falkordblite on Python 3.12+

cd frontend && npm ci && npm run build && cd ..

mkdir -p .data
CUSTODY_FALKORDB_EMBEDDED_PATH=.data/custody.db \
CUSTODY_STATIC_DIR=frontend/dist \
uvicorn custody.api.app:app --port 8000
```

Open [http://localhost:8000](http://localhost:8000). The `mkdir` matters: the embedded database refuses to start if the folder for its file does not exist (see [Troubleshooting](/docs/troubleshooting#embedded-falkordb-fails-to-start)).

> [!TIP]
> For frontend work, run the API with `make api-embedded` and the console with `make ui` instead. The Vite dev server on port 5173 reloads on save and proxies `/api` to the API on port 8000. The [installation guide](/docs/installation) covers every option.

## Run the attack

The dashboard starts empty. Click **Run attack scenario**.

![The empty dashboard with the Run attack scenario button](console-empty.webp "A fresh tenant: one button records the simulated Day 1 and Day 4 sessions.")

The console wipes the `acme` tenant graph, records the scripted story through the real agent runtime and the real Guard, and opens the **Attack demo** page, which plays the seven steps:

![The seven-step timeline: steps 5 and 6 carry ALLOW and BLOCK badges](demo-timeline.webp "Step 5 (internal Slack post) is allowed; step 6 (upload to the attacker's URL) is blocked.")

1. Click step **5**. Ops posts the rotated key to `#platform-team`. The destination is exactly what the user typed, and the Slack workspace is internal, so the Guard returns **ALLOW** and attaches a provenance completeness certificate.
2. Click step **6**. Ops proposes `upload_backup` to the URL it recalled from shared memory. The destination traces back to an untrusted page, the payload is a secret and the sink is external: a lethal trifecta. **BLOCK**, with no approval option.
3. Click step **7**, then **Open decision**. The Guard decision page shows every check, the provenance route, the latency of each query and the audit trail stored in the graph.

![Step 7: the provenance path from the blocked upload back to the vendor page](demo-step7-path.webp "The explanation is the path itself: action → sink → destination → previous-session memory → web page → untrusted source.")

## Next

- The [Console tour](/docs/console) walks through every page, including the provenance graph, approvals and the Warden.
- [Demo scenarios](/docs/demos) covers the three-worlds comparison and the extended scenario used for incident response.
- The same story runs in a terminal: `python scripts/attack_demo.py --embedded .data/cli.db`.
- The documentation you are reading is served by the same app at `/docs`.
