# Demo fixtures

`llm_run.json` (not committed until someone records it) is one real LLM-driven run of the
primary scenario, written by `python scripts/record_llm_run.py` (needs `ANTHROPIC_API_KEY`).
The demo replays it with no model call (`CUSTODY_DEMO_MODE=auto` only replays a
real-model recording that contains a BLOCK; `recorded` also accepts a test-double
recording); see "Recorded LLM execution, deterministic replay" in the README.
It holds only the synthetic scenario (prompts, the synthetic vendor page, the fake vault
key, model outputs, request hashes). It never contains an API key.
