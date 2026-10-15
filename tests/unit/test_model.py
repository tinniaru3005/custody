"""Pure unit tests (no database)."""
import pytest

from custody.db import InvalidTenant, graph_name
from custody.graph.model import Sensitivity, fingerprint, safe_preview
from custody.recorder.service import sink_id


def test_graph_name_per_tenant():
    assert graph_name("acme") == "custody:acme"
    assert graph_name("acme", prefix="x") == "x:acme"


@pytest.mark.parametrize("bad", ["", "Acme", "a b", "a:b", "-x", "x" * 64, "../etc"])
def test_invalid_tenants_rejected(bad):
    with pytest.raises(InvalidTenant):
        graph_name(bad)


def test_sensitivity_max():
    assert Sensitivity.max() == Sensitivity.NORMAL
    assert Sensitivity.max("normal", "sensitive") == Sensitivity.SENSITIVE
    assert Sensitivity.max("secret", "normal", "sensitive") == Sensitivity.SECRET


def test_secret_preview_masks_value():
    secret = "AKIAACMEROBOTICS0000EXAMPLEKEY"
    preview = safe_preview(secret, Sensitivity.SECRET)
    assert secret not in preview
    assert preview.startswith("[secret:")


def test_normal_preview_truncates():
    assert safe_preview("x" * 500, Sensitivity.NORMAL).endswith("…")
    assert len(safe_preview("x" * 500, Sensitivity.NORMAL)) == 200


def test_fingerprint_and_sink_id_are_stable():
    assert fingerprint("a") == fingerprint("a") != fingerprint("b")
    assert sink_id("email", "a@b.c") == sink_id("email", "a@b.c")
    assert sink_id("email", "a@b.c") != sink_id("http", "a@b.c")
