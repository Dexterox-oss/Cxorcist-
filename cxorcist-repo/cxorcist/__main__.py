from __future__ import annotations

import argparse
import json
import os
import sys

from . import alerts, pipeline
from .llm import GroqClient
from .models import sev_rank


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="cxorcist", description="Dependency, vulnerability and code-issue scanner")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sc = sub.add_parser("scan", help="scan a repo folder")
    sc.add_argument("path")
    sc.add_argument("--llm", action="store_true", help="triage findings with Groq (needs GROQ_API_KEY)")
    sc.add_argument("--offline", action="store_true", help="skip the OSV network lookup")
    sc.add_argument("--max-llm", type=int, default=15, help="max findings sent to the LLM")
    sc.add_argument("--cache", default=".cxorcist_cache.json", help="LLM result cache file ('' to disable)")
    sc.add_argument("--out", help="write full JSON report here")
    sc.add_argument("--alert-url", default=os.environ.get("N8N_WEBHOOK_URL"), help="POST critical/high summary here")
    sc.add_argument("--fail-on", choices=["critical", "high", "medium", "low"], help="exit 2 if any finding is at/above this")
    args = ap.parse_args(argv)

    llm = GroqClient() if args.llm else None
    report = pipeline.run(args.path, llm=llm, offline=args.offline, max_llm=args.max_llm,
                          cache_path=args.cache or None)
    s = report["summary"]
    print(f"Scanned {s['dependencies']} dependencies {s['ecosystems']} in {report['duration_seconds']}s")
    print(f"Findings: {s['findings_total']}  {s['by_severity']}  "
          f"(vulns: {s['vulnerable_packages']}, code issues: {s['code_issues']}, "
          f"auto-fixable: {s['auto_fixable']}, needs human: {s['needs_human']})")
    if args.llm:
        print(f"LLM calls: {s['llm_calls']}, cache hits: {s['cache_hits']}")
    for f in report["findings"][:15]:
        where = f"{f['package']}@{f['version']}" if f["kind"] == "vulnerability" else f"{f['file']}:{f['line']}"
        fix = f["fixed_in"] and f" -> fix {f['fixed_in']}" or ""
        print(f"  [{f['severity'].upper():8}] {where}  {f['title'][:70]}{fix}  ({f['tier']})")
    for e in report["errors"]:
        print(f"  ! {e}", file=sys.stderr)

    if args.out:
        with open(args.out, "w") as fh:
            json.dump(report, fh, indent=2)
        print(f"Full report: {args.out}")
    if args.alert_url and (s["by_severity"]["critical"] or s["by_severity"]["high"]):
        alerts.post_alert(args.alert_url, report)
        print("Alert payload sent to webhook.")
    if args.fail_on and any(sev_rank(f["severity"]) <= sev_rank(args.fail_on) for f in report["findings"]):
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
