"""The benchmark scripts stay runnable (tiny configurations; numbers are not asserted)."""
import json

from bench import run_correctness, run_scaling
from bench.common import connect


def test_correctness_benchmark_runs(tmp_path):
    assert run_correctness.main(["--variants", "1", "--repeats", "2",
                                 "--out", str(tmp_path)]) == 0
    r = json.loads((tmp_path / "correctness.json").read_text())
    from bench.cases import FAMILIES
    assert r["config"]["cases"] == len(FAMILIES)
    # deterministic methods: one distinct verdict per case across repeats
    assert all(v == 1 for row in r["rows"] for k, v in row["info"]["distinct_verdicts"].items())
    # the report runs on this output and writes the four figures
    from bench import report
    assert report.main(["--results", str(tmp_path)]) == 0
    assert {p.name for p in (tmp_path / "figures").iterdir()} >= {
        "heatmap.png", "paraphrase_depth.png", "negative_claims.png", "determinism.png"}
    text = (tmp_path / "REPORT.md").read_text()
    assert "Circularity caveat" in text and "Falsification" in text
    assert r["custody_outcomes"]["INDETERMINATE"] == 0
    # Custody and the recursive CTE implement the same semantics over the same edges
    assert all(row["pred"]["custody"] == row["pred"]["sql_cte"] for row in r["rows"])
    assert (tmp_path / "correctness.md").read_text().startswith("# Correctness benchmark")


def test_scaling_measure_point():
    db, _ = connect()
    for dangerous in (True, False):
        row = run_scaling.measure(db, "chain", run_scaling.gen_chain, (30,), dangerous, reps=1)
        assert row["correct"] and row["sql_cte"]["found"] is dangerous
        assert row["old_bounded_query_25"]["found"] is False   # the pre-fix blind spot


def test_large_benchmark_points():
    """run_large's generators and measurement on tiny graphs (both limit sets)."""
    from bench import run_large

    db, _ = connect()
    for gen, params in ((run_large.gen_fanin, (40,)), (run_large.gen_tree, (3, 2)),
                        (run_large.gen_chain, (30, 20))):
        for dangerous in (True, False):
            row = run_large.measure(db, gen.__name__, gen, params, dangerous, reps=1)
            for cfg in ("default", "raised"):
                c = row["configs"][cfg]
                assert c["search"]["complete"] and c["correct"] is True
                assert (c["guard"]["verdict"] == "ALLOW") is (not dangerous)
                assert c["guard"]["certificate"] is (not dangerous)
            assert row["sql_cte"]["found"] is dangerous
    assert "| scenario |" in run_large.render({"machine": run_large.machine_info("x"),
                                               "command": "x", "reps": 1, "rows": [row]})
