"""End-to-end run: scan deps -> OSV lookup -> code checks -> LLM triage -> deterministic policy."""
from __future__ import annotations

import hashlib
import json
import time
from collections import Counter
from pathlib import Path
from typing import Callable

from . import codecheck, osv, risk
from .ignore import load_patterns, make_matcher
from .llm import LLMClient, LLMError, triage
from .models import Finding, sev_rank
from .net import http_json
from .scanner import Dependency, scan


def _max_severity(sevs: list[str | None]) -> str | None:
    known = [s for s in sevs if s]
    return min(known, key=sev_rank) if known else None


def vulnerability_findings(deps, http: Callable[..., dict], errors: list[dict]) -> list[Finding]:
    try:
        vulnerable = osv.find_vulnerable(deps, http)
    except Exception as e:  # network failure must not kill the whole report
        errors.append({"stage": "osv", "error": str(e)})
        return []
    out = []
    for dep, ids in vulnerable:
        advs = []
        for vid in ids[:10]:
            try:
                advs.append(osv.fetch_advisory(vid, http))
            except Exception as e:
                errors.append({"stage": "osv-advisory", "id": vid, "error": str(e)})
        sev = _max_severity([osv.advisory_severity(a) for a in advs])
        source = "osv" if sev else "default"
        sev = sev or "medium"
        fixed = osv.pick_fix(advs, dep.ecosystem, dep.name, dep.version) if advs else ""
        tier, reason = risk.decide(sev, source, dep.version, fixed)
        summary = next((a.get("summary") for a in advs if a.get("summary")), "")
        out.append(Finding(
            kind="vulnerability", rule=", ".join(ids[:5]),
            title=f"{len(ids)} known advisor{'y' if len(ids) == 1 else 'ies'} in {dep.name}@{dep.version}"
                  + (f": {summary[:100]}" if summary else ""),
            severity=sev, severity_source=source, file=dep.source_file, package=dep.name,
            version=dep.version, ecosystem=dep.ecosystem, fixed_in=fixed,
            suggested_fix=osv.suggest_fix_command(dep.ecosystem, dep.name, fixed),
            advisories=ids, tier=tier, tier_reason=reason))
    return out


def _cache_key(f: Finding, model: str) -> str:
    # The model is part of the key: switching models must not reuse another model's answers.
    raw = "|".join([model, f.kind, f.rule, f.package, f.version, f.file, str(f.line), f.snippet])
    return hashlib.sha256(raw.encode()).hexdigest()


def _load_cache(cache_path: str | None) -> dict:
    if cache_path and Path(cache_path).exists():
        try:
            data = json.loads(Path(cache_path).read_text())
            return data if isinstance(data, dict) else {}
        except (OSError, json.JSONDecodeError):
            return {}   # a corrupt cache is ignored, never fatal
    return {}


def apply_llm(findings: list[Finding], client: LLMClient, max_calls: int, cache_path: str | None,
              errors: list[dict]) -> dict:
    model = getattr(client, "model", "")
    cache = _load_cache(cache_path)
    calls = hits = failed = 0
    for f in sorted(findings, key=lambda x: sev_rank(x.severity))[:max_calls]:
        key = _cache_key(f, model)
        result = cache.get(key)
        if result:
            hits += 1
        else:
            calls += 1
            try:
                result = triage(client, f)
            except LLMError as e:
                errors.append({"stage": "llm", "error": str(e)})
                failed += 1
                if e.fatal:
                    break          # bad key / retired model: stop calling, keep the rest of the report
                continue
            if result:
                cache[key] = result    # only successful answers are cached; failures are retried next run
            else:
                failed += 1
        f.llm = result
        # Guardrails: the LLM may only fill in a missing severity. It can never lower a
        # confirmed severity, and it can never turn a finding into auto_fixable.
        if result and f.severity_source == "default":
            f.severity, f.severity_source = result["severity"], "llm"
    if cache_path:
        try:
            Path(cache_path).write_text(json.dumps(cache, indent=2))
        except OSError as e:
            errors.append({"stage": "cache", "error": str(e)})
    return {"llm_calls": calls, "cache_hits": hits, "llm_failed": failed}


def run(path: str, *, llm: LLMClient | None = None, http: Callable[..., dict] = http_json,
        offline: bool = False, max_llm: int = 15, cache_path: str | None = None,
        ignore_patterns: list[str] | None = None) -> dict:
    t0 = time.time()
    root = Path(path).resolve()
    patterns = load_patterns(root, ignore_patterns)
    ignore = make_matcher(patterns) if patterns else None

    report = scan(path, ignore)
    errors = list(report["errors"])
    deps = [Dependency(**d) for d in report["dependencies"]]
    # Dependencies declared only as a range (no lockfile) cannot be matched to advisories.
    unchecked = [{"ecosystem": d.ecosystem, "name": d.name, "file": d.source_file} for d in deps if not d.version]

    findings: list[Finding] = []
    if not offline:
        findings += vulnerability_findings(deps, http, errors)
    code_findings, code_errors = codecheck.check_repo(path, ignore)
    findings += code_findings
    errors += code_errors

    llm_stats = {"llm_calls": 0, "cache_hits": 0, "llm_failed": 0}
    if llm and findings:
        llm_stats = apply_llm(findings, llm, max_llm, cache_path, errors)

    findings.sort(key=lambda f: (sev_rank(f.severity), f.kind, f.file, f.line))
    sev_counts = Counter(f.severity for f in findings)
    return {
        "scanned_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "root": report["root"],
        "duration_seconds": round(time.time() - t0, 2),
        "ignored_patterns": patterns,
        "summary": {
            "dependencies": report["dependency_count"],
            "unpinned_dependencies": len(unchecked),
            "ecosystems": report["ecosystems"],
            "findings_total": len(findings),
            "by_severity": {s: sev_counts.get(s, 0) for s in ("critical", "high", "medium", "low")},
            "vulnerable_packages": sum(1 for f in findings if f.kind == "vulnerability"),
            "code_issues": sum(1 for f in findings if f.kind == "code_issue"),
            "auto_fixable": sum(1 for f in findings if f.tier == "auto_fixable"),
            "needs_human": sum(1 for f in findings if f.tier in ("escalate", "review")),
            "offline": offline,
            **llm_stats,
        },
        "unchecked_dependencies": unchecked,
        "findings": [f.__dict__ for f in findings],
        "errors": errors,
    }
