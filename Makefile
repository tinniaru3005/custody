# Common tasks. Python commands use .venv; see README for setup.
PY ?= .venv/bin/python
EMBEDDED ?= .data/custody.db

.PHONY: install api api-embedded api-public ui test test-backend test-frontend e2e lint fixtures demo build bench bench-large

install:
	python3 -m venv .venv && $(PY) -m pip install -e ".[dev,warden,bench]"
	cd frontend && npm ci

api:            ## API against CUSTODY_FALKORDB_* (local server / FalkorDB Cloud)
	$(PY) -m uvicorn custody.api.app:app --reload --port 8000

api-embedded:   ## API with an embedded FalkorDB (no Docker)
	mkdir -p .data && CUSTODY_FALKORDB_EMBEDDED_PATH=$(EMBEDDED) $(PY) -m uvicorn custody.api.app:app --reload --port 8000

api-public:     ## public-demo mode: one read-only synthetic tenant + Reset Demo
	mkdir -p .data && CUSTODY_PUBLIC_DEMO=true CUSTODY_FALKORDB_EMBEDDED_PATH=.data/public.db \
	  CUSTODY_STATIC_DIR=frontend/dist $(PY) -m uvicorn custody.api.app:app --port 8000

ui:
	cd frontend && npm run dev

demo:
	$(PY) scripts/attack_demo.py

bench:          ## reproducible benchmarks → bench/results/
	$(PY) -m bench.run_correctness
	$(PY) -m bench.run_scaling
	$(PY) -m bench.run_sql_compare
	$(PY) -m bench.run_llm_adversarial
	$(PY) -m bench.report

bench-large:    ## 100k+ node graphs (~17 min on 2 vCPU) → bench/results/large.*
	$(PY) -m bench.run_large

lint:
	$(PY) -m ruff check custody tests scripts bench
	cd frontend && npm run lint && npm run typecheck && npm run format:check

test-backend:
	$(PY) -m pytest -q

test-frontend:
	cd frontend && npm test

e2e: build
	cd frontend && npx playwright test

test: lint test-backend test-frontend e2e

build:
	cd frontend && npm run build

fixtures:
	$(PY) scripts/export_ui_fixtures.py
