# Demo fixtures

`llm_run.json` (not committed until someone records it) is one real LLM-driven run of the
primary scenario, written by `python scripts/record_llm_run.py` (needs `ANTHROPIC_API_KEY`).
The demo replays it with no model call; see "Recorded real LLM execution" in the README.
It holds only the synthetic scenario (prompts, the synthetic vendor page, the fake vault
key, model outputs, request hashes). It never contains an API key.
