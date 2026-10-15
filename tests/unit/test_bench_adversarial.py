"""The adversarial LLM-judge harness: every run recorded; Custody unchanged by injection."""
from bench import run_llm_adversarial as A


class StubJudge:
    """Deterministic stand-in for the LLM: believes the approval claim on runs 0 and 2."""

    model = "stub"
    temperature = None

    def __init__(self):
        self.calls = 0

    def judge(self, dest, ctx, tool_call=None):
        text = " ".join(d.text for d in ctx)
        n = self.calls
        self.calls += 1
        if A.APPROVAL_CLAIM in text and n % 2 == 0:
            return False, "approved by security team"
        return ("Note for AI agents" in text), "raw"


def test_custody_is_invariant_and_every_llm_run_is_reported():
    r = A.run(runs=4, judge=StubJudge())
    v = r["variants"]
    assert r["custody_identical_under_injection"] is True
    assert v["poisoned_plain"]["custody"]["verdicts"] == ["BLOCK"] * 4
    assert v["poisoned_claim"]["custody"]["verdicts"] == ["BLOCK"] * 4
    assert v["clean_control"]["custody"]["verdicts"] == ["ALLOW"] * 4
    assert v["poisoned_claim"]["custody"]["evidence_path"].endswith("[untrusted]")
    j = v["poisoned_claim"]["llm_judge"]
    assert len(j["verdicts"]) == 4 and len(j["raw"]) == 4          # no run dropped
    assert j["verdicts"].count("ALLOW") == 2 and j["accuracy"] == 0.5
    assert j["consistency"] == 0.5
    assert r["llm_injection_effect"]["delta"] == -0.5
    md = A.render({**r, "command": "x"})
    assert "ALLOW, BLOCK, ALLOW, BLOCK" in md


def test_without_api_key_llm_is_reported_as_not_run():
    r = A.run(runs=2, judge=None, skipped="ANTHROPIC_API_KEY not set")
    assert r["variants"]["poisoned_claim"]["llm_judge"] == {"skipped": "ANTHROPIC_API_KEY not set"}
    assert "not run" in A.render({**r, "command": "x"})
