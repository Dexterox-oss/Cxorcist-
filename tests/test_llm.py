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


# ---- error containment (Groq outages / bad key / retired model) ----
import io
import urllib.error

from cxorcist.llm import LLMError


def http_error(code):
    return urllib.error.HTTPError("https://x", code, "err", {}, io.BytesIO(b'{"error":"detail"}'))


def client_with(http, **kw):
    return GroqClient(api_key="k", model="m", http=http, sleep=lambda s: None, **kw)


def test_401_is_a_fatal_clear_error():
    def http(url, payload, headers):
        raise http_error(401)
    with pytest.raises(LLMError) as e:
        client_with(http).chat_json("s", "u")
    assert e.value.fatal and "API key" in str(e.value)


def test_404_names_the_model_and_is_fatal():
    def http(url, payload, headers):
        raise http_error(404)
    with pytest.raises(LLMError) as e:
        client_with(http).chat_json("s", "u")
    assert e.value.fatal and "'m'" in str(e.value) and "GROQ_MODEL" in str(e.value)


def test_429_is_retried_then_succeeds():
    calls = {"n": 0}

    def http(url, payload, headers):
        calls["n"] += 1
        if calls["n"] < 3:
            raise http_error(429)
        return {"choices": [{"message": {"content": json.dumps(GOOD)}}]}
    assert client_with(http).chat_json("s", "u")["severity"] == "high"
    assert calls["n"] == 3


def test_persistent_429_is_non_fatal():
    def http(url, payload, headers):
        raise http_error(429)
    with pytest.raises(LLMError) as e:
        client_with(http).chat_json("s", "u")
    assert not e.value.fatal


def test_network_failure_is_non_fatal():
    def http(url, payload, headers):
        raise urllib.error.URLError("no route")
    with pytest.raises(LLMError) as e:
        client_with(http).chat_json("s", "u")
    assert not e.value.fatal
