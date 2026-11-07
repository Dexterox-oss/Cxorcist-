"""Vulnerability lookup against OSV.dev (free, no API key)."""
from __future__ import annotations

import re
from typing import Callable

from .risk import parse_version
from .scanner import Dependency

OSV_BATCH = "https://api.osv.dev/v1/querybatch"
OSV_VULN = "https://api.osv.dev/v1/vulns/{}"
Http = Callable[..., dict]

_SEV_MAP = {"CRITICAL": "critical", "HIGH": "high", "MODERATE": "medium", "MEDIUM": "medium", "LOW": "low"}


def _norm(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def find_vulnerable(deps: list[Dependency], http: Http) -> list[tuple[Dependency, list[str]]]:
    """Return (dependency, advisory_ids) for pinned deps with known advisories."""
    pinned = [d for d in deps if d.version]
    out: list[tuple[Dependency, list[str]]] = []
    for i in range(0, len(pinned), 500):
        chunk = pinned[i:i + 500]
        queries = [{"package": {"name": d.name, "ecosystem": d.ecosystem}, "version": d.version} for d in chunk]
        results = http(OSV_BATCH, {"queries": queries}).get("results", [])
        for dep, res in zip(chunk, results):
            ids = [v["id"] for v in res.get("vulns", [])]
            if ids:
                out.append((dep, ids))
    return out


def fetch_advisory(vuln_id: str, http: Http) -> dict:
    return http(OSV_VULN.format(vuln_id))


def advisory_severity(adv: dict) -> str | None:
    sev = (adv.get("database_specific") or {}).get("severity")
    return _SEV_MAP.get(str(sev).upper()) if sev else None


def fixed_versions(adv: dict, ecosystem: str, name: str, current: str) -> list[str]:
    """Smallest fixed version above `current` for each affected entry of this package."""
    cur = parse_version(current)
    best: list[str] = []
    for aff in adv.get("affected", []):
        pkg = aff.get("package", {})
        if pkg.get("ecosystem") != ecosystem or _norm(pkg.get("name", "")) != _norm(name):
            continue
        cands = [e["fixed"] for r in aff.get("ranges", []) for e in r.get("events", []) if "fixed" in e]
        cands = [c for c in cands if parse_version(c) and cur and parse_version(c) > cur]
        if cands:
            best.append(min(cands, key=lambda c: parse_version(c)))
    return best


def pick_fix(advisories: list[dict], ecosystem: str, name: str, current: str) -> str:
    """One version that fixes all advisories: the highest of each advisory's minimal fix."""
    per_adv = []
    for adv in advisories:
        fixes = fixed_versions(adv, ecosystem, name, current)
        if not fixes:
            return ""  # at least one advisory has no known fix above the current version
        per_adv.append(min(fixes, key=lambda c: parse_version(c)))
    return max(per_adv, key=lambda c: parse_version(c)) if per_adv else ""


def suggest_fix_command(ecosystem: str, name: str, fixed: str) -> str:
    cmds = {
        "PyPI": f"pip install '{name}>={fixed}'",
        "npm": f"npm install {name}@{fixed}",
        "Go": f"go get {name}@v{fixed}",
        "crates.io": f"cargo update -p {name} --precise {fixed}",
        "RubyGems": f"bundle update {name}",
        "Packagist": f"composer update {name}",
        "NuGet": f"dotnet add package {name} --version {fixed}",
        "Maven": f"set {name} to version {fixed} in your pom.xml / build.gradle",
    }
    return cmds.get(ecosystem, f"upgrade {name} to {fixed}") if fixed else ""
