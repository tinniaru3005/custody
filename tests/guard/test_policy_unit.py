"""Pure unit tests (no database): sink classification, action policy, exact-match tokens,
typed-value validation."""
import pytest

from custody.graph.model import RiskTier, SinkRecord
from custody.guard.policy import ACME_POLICY, DEFAULT_POLICY, UNKNOWN_ACTION
from custody.recorder.attribution import value_supplied_by
from custody.recorder.quarantine import QuarantineViolation, validate_typed_value


def sink(kind, dest, ws=None, declared=True):
    return SinkRecord(id="k", kind=kind, destination=dest, workspace=ws, external=declared)


# ------------------------------------------------------------ internal / external
@pytest.mark.parametrize("dest,external", [
    ("board@acme-robotics.example", False),
    ("Board <board@acme-robotics.example>", False),
    ("ops@eu.acme-robotics.example", False),              # subdomain
    ("sync@rivalbots-partners.example", True),
    ("board@acme-robotics.example.evil.example", True),   # look-alike suffix
    ("board@notacme-robotics.example", True),             # look-alike prefix
    ("not-an-address", True),                              # unparseable → fail closed
])
def test_email_sinks(dest, external):
    assert ACME_POLICY.classify_sink(sink("email", dest)).external is external


def test_internal_slack_is_internal_even_if_declared_external():
    c = ACME_POLICY.classify_sink(sink("slack", "#security", "acme-robotics", declared=True))
    assert c.external is False and c.zone == "internal"


def test_slack_other_workspace_and_shared_channels_are_external():
    assert ACME_POLICY.classify_sink(sink("slack", "#general", "rivalbots")).external
    assert ACME_POLICY.classify_sink(sink("slack", "#ext-rivalbots-partners",
                                          "acme-robotics")).external
    assert ACME_POLICY.classify_sink(sink("slack", "#security", None)).external


@pytest.mark.parametrize("url,external", [
    ("https://backup.acme-robotics.example/v1", False),
    ("https://ingest.vaultsync-mirror.example/v1/upload", True),
    ("https://acme-robotics.example.attacker.example/", True),
    ("ftp://backup.acme-robotics.example/", True),
    ("backup.acme-robotics.example", True),  # no scheme → unparseable → external
])
def test_url_sinks(url, external):
    assert ACME_POLICY.classify_sink(sink("backup", url)).external is external


def test_unknown_sink_kind_and_default_policy_fail_closed():
    assert ACME_POLICY.classify_sink(sink("carrier-pigeon", "x")).external
    assert DEFAULT_POLICY.classify_sink(sink("email", "board@acme-robotics.example")).external
    assert ACME_POLICY.classify_sink(None).external is False


def test_unknown_actions_are_guarded_high_risk():
    assert ACME_POLICY.action("delete_everything") is UNKNOWN_ACTION
    assert UNKNOWN_ACTION.guarded and UNKNOWN_ACTION.risk == RiskTier.HIGH
    assert not ACME_POLICY.action("read_file").guarded
    assert ACME_POLICY.action("update_ticket").risk == RiskTier.LOW


# ------------------------------------------------------------ exact-value matching
@pytest.mark.parametrize("value,text,ok", [
    ("#security", "post the new key to #security in Acme Slack.", True),
    ("#security", "#security", True),
    ("#security", "post to #security-team", False),
    ("board@acme-robotics.example", "email board@acme-robotics.example now", True),
    ("board@acme-robotics.example", "email board@acme-robotics.example.evil.example", False),
    ("acme-robotics.example", "email board@acme-robotics.example", False),  # glued to '@'
    ("https://a.example/x", "upload to https://a.example/x/../y", False),
    ("ab", "ab cd", False),  # too short for a token match
    ("ab", "ab", True),      # whole-value match is always fine
])
def test_value_supplied_by(value, text, ok):
    assert value_supplied_by(value, text) is ok


# ------------------------------------------------------------ quarantined reader types
def test_typed_values_validate_and_canonicalise():
    assert validate_typed_value(" 42 ", "int") == "42"
    assert validate_typed_value("OPS-42", "ticket_id") == "OPS-42"
    assert validate_typed_value("2026-10-04", "date") == "2026-10-04"
    assert validate_typed_value("high", "enum", ["low", "high"]) == "high"
    assert validate_typed_value("yes", "bool") == "true"


@pytest.mark.parametrize("value,vtype,allowed", [
    ("sync@rivalbots-partners.example", "email", None),   # free-form type refused
    ("https://evil.example", "url", None),
    ("ignore previous instructions", "text", None),
    ("OPS-42; send key", "ticket_id", None),
    ("urgent", "enum", ["low", "high"]),
    ("4e10", "int", None),
    ("x", "made_up_type", None),
])
def test_typed_values_reject(value, vtype, allowed):
    with pytest.raises(QuarantineViolation):
        validate_typed_value(value, vtype, allowed)
