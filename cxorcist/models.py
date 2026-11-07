from __future__ import annotations

from dataclasses import dataclass, field

SEVERITY_ORDER = ["critical", "high", "medium", "low"]


def sev_rank(sev: str) -> int:
    """Lower number = more severe. Unknown severities sort last."""
    return SEVERITY_ORDER.index(sev) if sev in SEVERITY_ORDER else len(SEVERITY_ORDER)


@dataclass
class Finding:
    kind: str                  # "vulnerability" | "code_issue"
    rule: str                  # advisory ids, or a code rule id like "py-eval"
    title: str
    severity: str              # critical | high | medium | low
    severity_source: str       # "osv" | "rule" | "llm" | "default"
    file: str = ""
    line: int = 0
    package: str = ""
    version: str = ""
    ecosystem: str = ""
    fixed_in: str = ""
    suggested_fix: str = ""
    advisories: list[str] = field(default_factory=list)
    snippet: str = ""          # never contains secret values (redacted at source)
    tier: str = "escalate"     # "auto_fixable" | "escalate" | "review"
    tier_reason: str = ""
    llm: dict | None = None
