"""Unit tests for the benchmark's content baselines and case generators (no numbers)."""
import base64
import random

from bench import baselines as B
from bench.cases import (_TRANSFORMS, DEEP_HOPS, FAMILIES, NEGATIVE_CATEGORIES,
                         POSITIVE_CATEGORIES, category)
from bench.common import Doc, fresh, connect

KEY = "AKIAROTATED0001ABCDEF12KEY"


def test_dlp_baselines_by_transform():
    inv = [KEY]
    t = {name: f(KEY) for name, f in _TRANSFORMS.items()}
    assert B.dlp_exact(t["identity"], inv) and not B.dlp_exact(t["base64"], inv)
    assert B.dlp_decode(t["base64"], inv) and B.dlp_decode(t["hex"], inv)
    assert B.dlp_decode(t["truncate"], inv)
    assert not B.dlp_decode(t["reverse"], inv) and not B.dlp_decode(t["dash_split"], inv)
    assert B.dlp_pattern("AKIAIOSFODNN7EXAMPLE")                  # a pattern can't tell
    assert not B.dlp_decode("nightly backup manifest 3", inv)
    assert base64.b64decode(t["base64"]).decode() == KEY


def _docs():
    mk = lambda i, text, trust: Doc(i, text, "s", "web_content", f"src{i}", trust)  # noqa: E731
    return {"a": mk("a", "Team backup destination: https://ingest42.mirror.example/v1/up", "untrusted"),
            "b": mk("b", "Relay: send it to https://ingest42.mirror.example/v1/up tonight", None),
            "c": mk("c", "Retention is 30 days.", "trusted")}


def test_vector_models_and_chain_are_deterministic():
    for kind in ("tfidf", "lsa"):
        idx = B.VectorIndex(_docs(), kind)
        q = "https://ingest42.mirror.example/v1/up"
        assert idx.top(q, 3) == idx.top(q, 3)
        assert idx.top(q, 1)[0][0] > 0
    idx = B.VectorIndex(_docs(), "tfidf")
    assert idx.chain_flag("https://ingest42.mirror.example/v1/up", 0.2) is True
    assert idx.chain_flag("completely unrelated words", 0.9) is False


def test_every_family_has_a_category_and_deep_chains_have_exact_hops():
    db, _ = connect()
    _, rec, guard, rt = fresh(db, "bench-unit-families")
    from bench.cases import build_all
    cases = build_all(rt, 1, 7)
    assert len(cases) == len(FAMILIES)
    for c in cases:
        cat = category(c.family)
        assert cat in (POSITIVE_CATEGORIES if c.label == "dangerous" else NEGATIVE_CATEGORIES)
    deep = [c for c in cases if c.family.startswith("D_deep")]
    for c in deep:
        d = guard.check(c.action_id)
        ev = next(p for p in d.paths if p.check.value == "integrity" and p.status == "violating")
        assert ev.length == c.params["hops"] and c.params["hops"] in DEEP_HOPS
    assert random.Random(7).random() == random.Random(7).random()


def test_llm_cost_summary():
    from bench.run_llm_adversarial import cost
    v = {"x": {"llm_judge": {"usage": [{"input_tokens": 1000, "output_tokens": 100}] * 4}}}
    c = cost(v, 3.0, 15.0)
    assert c["decisions"] == 4 and c["mean_input_tokens"] == 1000
    assert c["usd_per_decision"] == round((4000 * 3 + 400 * 15) / 1e6 / 4, 6)
    assert cost({"x": {"llm_judge": {"skipped": "no key"}}}, None, None) is None
