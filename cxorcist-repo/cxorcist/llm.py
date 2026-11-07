"""
Groq-backed triage. The LLM explains and prioritises; it never makes the
auto-fix decision (see risk.py) and never sees secret values (redacted upstream).
"""
from __future__ import annotations

import json
import os
from typing import Callable, Protocol

from .models import SEVERITY_ORDER, Finding
from .net import http_json

GROQ_URL = "https://api.groq.com/openai/v1/chat/completions"
DEFAULT_MODEL = "llama-3.3-70b-versatile"

SYSTEM_PROMPT = (
    "You are a security triage assistant. You receive ONE finding (a vulnerable dependency or a "
    "code issue) as JSON. Reply with ONLY a JSON object with keys: "
    'severity ("critical"|"high"|"medium"|"low"), urgent (boolean), '
    'action (string: one concrete next step), reason (string, max 30 words), '
    'confidence (number 0 to 1), false_positive ("low"|"medium"|"high": how likely this is NOT a real problem). '
    "Use only the information provided. Never invent CVE ids or versions."
)


class LLMClient(Protocol):
    def chat_json(self, system: str, user: str) -> dict: ...


class GroqClient:
    def __init__(self, api_key: str | None = None, model: str | None = None,
                 http: Callable[..., dict] = http_json, url: str = GROQ_URL):
        self.api_key = api_key or os.environ.get("GROQ_API_KEY", "")
        if not self.api_key:
            raise ValueError("GROQ_API_KEY is not set")
        self.model = model or os.environ.get("GROQ_MODEL", DEFAULT_MODEL)
        self.http, self.url = http, url

    def chat_json(self, system: str, user: str) -> dict:
        body = {"model": self.model, "temperature": 0, "response_format": {"type": "json_object"},
                "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}]}
        resp = self.http(self.url, body, {"Authorization": f"Bearer {self.api_key}"})
        return json.loads(resp["choices"][0]["message"]["content"])


def validate_triage(obj: dict) -> dict:
    """Strictly validate model output. Raises ValueError on anything malformed."""
    if not isinstance(obj, dict):
        raise ValueError("not an object")
    if obj.get("severity") not in SEVERITY_ORDER:
        raise ValueError("bad severity")
    if not isinstance(obj.get("urgent"), bool):
        raise ValueError("urgent must be boolean")
    if not isinstance(obj.get("action"), str) or not obj["action"].strip():
        raise ValueError("missing action")
    conf = obj.get("confidence")
    if isinstance(conf, bool) or not isinstance(conf, (int, float)) or not 0 <= conf <= 1:
        raise ValueError("bad confidence")
    fp = obj.get("false_positive", "low")
    if fp not in ("low", "medium", "high"):
        raise ValueError("bad false_positive")
    return {"severity": obj["severity"], "urgent": obj["urgent"], "action": obj["action"][:300],
            "reason": str(obj.get("reason", ""))[:200], "confidence": float(conf), "false_positive": fp}


def finding_payload(f: Finding) -> str:
    d = {"kind": f.kind, "title": f.title, "rule": f.rule, "severity_hint": f.severity,
         "file": f.file, "line": f.line, "snippet": f.snippet}
    if f.kind == "vulnerability":
        d.update(package=f.package, version=f.version, ecosystem=f.ecosystem,
                 fixed_in=f.fixed_in, advisories=f.advisories)
    return json.dumps(d)


def triage(client: LLMClient, f: Finding, retries: int = 2) -> dict | None:
    """Ask the model; retry on malformed output; return None if it never validates."""
    user = finding_payload(f)
    for _ in range(retries + 1):
        try:
            return validate_triage(client.chat_json(SYSTEM_PROMPT, user))
        except (ValueError, KeyError, json.JSONDecodeError, TypeError):
            continue
    return None
