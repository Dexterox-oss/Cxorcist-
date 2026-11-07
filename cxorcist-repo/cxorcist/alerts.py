"""Build and (optionally) send the payload an n8n webhook turns into a call + email."""
from __future__ import annotations

from typing import Callable

from .net import http_json


def build_payload(report: dict, top_n: int = 5) -> dict:
    sev = report["summary"]["by_severity"]
    important = [f for f in report["findings"] if f["severity"] in ("critical", "high")][:top_n]
    top = [{"title": f["title"], "severity": f["severity"], "location": f["package"] or f"{f['file']}:{f['line']}",
            "tier": f["tier"], "action": (f["llm"] or {}).get("action") or f["suggested_fix"] or f["tier_reason"]}
           for f in important]
    message = (f"Cxorcist scan found {sev['critical']} critical and {sev['high']} high severity issues "
               f"in {report['root'].split('/')[-1]}.")
    return {"source": "cxorcist", "root": report["root"], "scanned_at": report["scanned_at"],
            "critical_count": sev["critical"], "high_count": sev["high"],
            "total_findings": report["summary"]["findings_total"], "message": message, "top_findings": top}


def post_alert(url: str, report: dict, http: Callable[..., dict] = http_json) -> dict:
    return http(url, build_payload(report))
