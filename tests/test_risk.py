import pytest

from cxorcist.risk import RiskTier, classify_risk, decide, version_jump


def test_policy_table():
    assert classify_risk("critical", "patch") == RiskTier.AUTO_FIXABLE
    assert classify_risk("critical", "major") == RiskTier.ESCALATE
    assert classify_risk("high", "minor") == RiskTier.ESCALATE


def test_unknown_inputs_raise_instead_of_defaulting_safe():
    with pytest.raises(ValueError):
        classify_risk("apocalyptic", "patch")
    with pytest.raises(ValueError):
        classify_risk("high", "sideways")


def test_version_jump():
    assert version_jump("1.2.3", "1.2.9") == "patch"
    assert version_jump("1.2.3", "1.3.0") == "minor"
    assert version_jump("1.2.3", "2.0.0") == "major"
    assert version_jump("abc", "1.0.0") is None


def test_decide_fails_toward_escalation():
    assert decide("critical", "osv", "5.3", "5.3.1")[0] == "auto_fixable"
    assert decide("critical", "llm", "5.3", "5.3.1")[0] == "escalate"      # unconfirmed severity
    assert decide("critical", "osv", "5.3", "")[0] == "escalate"           # no fix available
    assert decide("critical", "osv", "weird", "1.0")[0] == "escalate"      # unparseable
