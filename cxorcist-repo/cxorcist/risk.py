"""
Deterministic risk policy for dependency fixes.

The LLM never decides whether something is safe to auto-fix. This table does.
Unknown inputs raise instead of silently defaulting to "safe".
"""
from __future__ import annotations

import re
from enum import Enum


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class VersionJump(str, Enum):
    PATCH = "patch"   # 1.2.3 -> 1.2.4
    MINOR = "minor"   # 1.2.3 -> 1.3.0
    MAJOR = "major"   # 1.2.3 -> 2.0.0


class RiskTier(str, Enum):
    AUTO_FIXABLE = "auto_fixable"
    ESCALATE = "escalate"


_RISK_RULES = {
    (Severity.CRITICAL, VersionJump.PATCH): RiskTier.AUTO_FIXABLE,
    (Severity.CRITICAL, VersionJump.MINOR): RiskTier.AUTO_FIXABLE,
    (Severity.CRITICAL, VersionJump.MAJOR): RiskTier.ESCALATE,
    (Severity.HIGH, VersionJump.PATCH): RiskTier.AUTO_FIXABLE,
    (Severity.HIGH, VersionJump.MINOR): RiskTier.ESCALATE,
    (Severity.HIGH, VersionJump.MAJOR): RiskTier.ESCALATE,
    (Severity.MEDIUM, VersionJump.PATCH): RiskTier.AUTO_FIXABLE,
    (Severity.MEDIUM, VersionJump.MINOR): RiskTier.ESCALATE,
    (Severity.MEDIUM, VersionJump.MAJOR): RiskTier.ESCALATE,
    (Severity.LOW, VersionJump.PATCH): RiskTier.AUTO_FIXABLE,
    (Severity.LOW, VersionJump.MINOR): RiskTier.ESCALATE,
    (Severity.LOW, VersionJump.MAJOR): RiskTier.ESCALATE,
}


def classify_risk(severity: str, version_jump: str) -> RiskTier:
    try:
        sev, jump = Severity(severity.lower()), VersionJump(version_jump.lower())
    except ValueError as exc:
        raise ValueError(f"Unrecognized severity/jump: {severity!r}/{version_jump!r}") from exc
    return _RISK_RULES[(sev, jump)]


def parse_version(v: str) -> tuple[int, int, int] | None:
    nums = re.findall(r"\d+", v or "")[:3]
    if not nums:
        return None
    return tuple(int(n) for n in nums + ["0"] * (3 - len(nums)))  # type: ignore[return-value]


def version_jump(current: str, fixed: str) -> str | None:
    """Return 'major' | 'minor' | 'patch', or None if either version can't be parsed."""
    cur, fix = parse_version(current), parse_version(fixed)
    if cur is None or fix is None:
        return None
    if fix[0] != cur[0]:
        return "major"
    if fix[1] != cur[1]:
        return "minor"
    return "patch"


def decide(severity: str, severity_source: str, current: str, fixed: str) -> tuple[str, str]:
    """Return (tier, reason) for a vulnerable dependency. Fails toward escalation."""
    if not fixed:
        return "escalate", "No fixed version is published; a human must choose a mitigation."
    if severity_source != "osv":
        return "escalate", "Severity is not confirmed by the advisory database; human review required."
    jump = version_jump(current, fixed)
    if jump is None:
        return "escalate", "Could not compare versions; human review required."
    tier = classify_risk(severity, jump)
    if tier == RiskTier.AUTO_FIXABLE:
        return "auto_fixable", f"{severity} severity, {jump} upgrade {current} -> {fixed} is low-risk to apply."
    return "escalate", f"{severity} severity needs a {jump} upgrade {current} -> {fixed}; breaking-change risk, human review."
