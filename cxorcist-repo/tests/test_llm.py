import json

import pytest

from cxorcist.llm import GroqClient, triage, validate_triage
from cxorcist.models import Finding

GOOD = {"severity": "high", "urgent": True, "action": "Upgrade", "reason": "x", "confidence": 0.9, "false_positive": "low"}


class Scripted:
    def __init__(self, outputs):
        self.outputs, self.calls = list(outputs), 0

    def chat_json(self, system, user):
        self.calls += 1
        out = self.outputs.pop(0)
        if isinstance(out, Exception):
            raise out
        return out


def finding():
    return Finding("code_issue", "py-eval", "eval", "high", "rule", file="a.py", line=1)


def test_validate_rejects_bad_output():
    for bad in ({**GOOD, "severity": "apocalyptic"}, {**GOOD, "urgent": "yes"}, {**GOOD, "confidence": 2},
                {**GOOD, "action": ""}, {**GOOD, "confidence": True}, "text"):
        with pytest.raises(ValueError):
            validate_triage(bad)


def test_triage_retries_malformed_then_succeeds():
    client = Scripted([{"junk": 1}, json.JSONDecodeError("x", "y", 0), GOOD])
    assert triage(client, finding())["severity"] == "high"
    assert client.calls == 3


def test_triage_gives_up_after_retries():
    client = Scripted([{"junk": 1}] * 3)
    assert triage(client, finding()) is None


def test_groq_client_parses_openai_style_response():
    seen = {}

    def fake_http(url, payload, headers):
        seen.update(url=url, auth=headers["Authorization"], model=payload["model"])
        return {"choices": [{"message": {"content": json.dumps(GOOD)}}]}

    out = GroqClient(api_key="k", model="m", http=fake_http).chat_json("s", "u")
    assert out["severity"] == "high"
    assert seen == {"url": "https://api.groq.com/openai/v1/chat/completions", "auth": "Bearer k", "model": "m"}


def test_missing_key_raises(monkeypatch):
    monkeypatch.delenv("GROQ_API_KEY", raising=False)
    with pytest.raises(ValueError):
        GroqClient()
