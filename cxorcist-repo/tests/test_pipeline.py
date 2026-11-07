import json

from conftest import FIXTURE
from cxorcist import alerts, pipeline

ADVISORIES = {
    "GHSA-req": {"summary": "requests leak", "database_specific": {"severity": "HIGH"},
                 "affected": [{"package": {"name": "requests", "ecosystem": "PyPI"},
                               "ranges": [{"events": [{"introduced": "0"}, {"fixed": "2.20.0"}]}]}]},
    "GHSA-yaml": {"summary": "yaml rce", "database_specific": {"severity": "CRITICAL"},
                  "affected": [{"package": {"name": "PyYAML", "ecosystem": "PyPI"},
                                "ranges": [{"events": [{"introduced": "0"}, {"fixed": "5.3.1"}]}]}]},
    "GHSA-lodash": {"summary": "lodash pollution",
                    "affected": [{"package": {"name": "lodash", "ecosystem": "npm"},
                                  "ranges": [{"events": [{"introduced": "0"}, {"fixed": "4.17.19"}]}]}]},
}
BY_PKG = {"requests": "GHSA-req", "pyyaml": "GHSA-yaml", "lodash": "GHSA-lodash"}


def fake_http(url, payload=None, headers=None):
    if url.endswith("querybatch"):
        return {"results": [{"vulns": [{"id": BY_PKG[q["package"]["name"].lower()]}]}
                            if q["package"]["name"].lower() in BY_PKG else {} for q in payload["queries"]]}
    return ADVISORIES[url.rsplit("/", 1)[-1]]


class FakeLLM:
    def __init__(self):
        self.calls = 0

    def chat_json(self, system, user):
        self.calls += 1
        return {"severity": "critical", "urgent": True, "action": "Do the thing", "reason": "r",
                "confidence": 0.8, "false_positive": "low"}


def by_pkg(report):
    return {f["package"]: f for f in report["findings"] if f["kind"] == "vulnerability"}


def test_vulnerability_findings_and_policy():
    r = pipeline.run(FIXTURE, http=fake_http)
    v = by_pkg(r)
    assert v["pyyaml"]["tier"] == "auto_fixable" and v["pyyaml"]["fixed_in"] == "5.3.1"   # critical + patch
    assert v["requests"]["tier"] == "escalate"                                           # high + minor
    assert v["lodash"]["severity_source"] == "default" and v["lodash"]["tier"] == "escalate"
    assert r["summary"]["code_issues"] > 5


def test_llm_cannot_override_policy_or_confirmed_severity(tmp_path):
    llm = FakeLLM()
    r = pipeline.run(FIXTURE, http=fake_http, llm=llm, max_llm=50, cache_path=str(tmp_path / "c.json"))
    v = by_pkg(r)
    assert v["lodash"]["severity"] == "critical" and v["lodash"]["severity_source"] == "llm"
    assert v["lodash"]["tier"] == "escalate"          # LLM severity never unlocks auto-fix
    assert v["requests"]["severity"] == "high"        # confirmed severity is not changed by the LLM
    assert v["requests"]["llm"]["action"] == "Do the thing"


def test_cache_prevents_repeat_llm_calls(tmp_path):
    cache = str(tmp_path / "c.json")
    first, second = FakeLLM(), FakeLLM()
    pipeline.run(FIXTURE, http=fake_http, llm=first, max_llm=50, cache_path=cache)
    r2 = pipeline.run(FIXTURE, http=fake_http, llm=second, max_llm=50, cache_path=cache)
    assert first.calls > 0 and second.calls == 0 and r2["summary"]["cache_hits"] == first.calls


def test_osv_outage_does_not_kill_the_scan():
    def broken(url, payload=None, headers=None):
        raise OSError("network down")
    r = pipeline.run(FIXTURE, http=broken)
    assert r["summary"]["code_issues"] > 5
    assert any(e.get("stage") == "osv" for e in r["errors"])


def test_report_has_no_secret_values():
    assert "hunter2hunter2" not in json.dumps(pipeline.run(FIXTURE, http=fake_http))


def test_alert_payload():
    r = pipeline.run(FIXTURE, http=fake_http)
    p = alerts.build_payload(r)
    assert p["source"] == "cxorcist" and p["critical_count"] >= 1 and p["top_findings"]
