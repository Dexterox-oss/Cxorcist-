"""Tiny HTTP helper. Injectable everywhere so tests never touch the network."""
from __future__ import annotations

import json
import urllib.request

# Some APIs (e.g. Groq behind Cloudflare) reject Python's default User-Agent.
USER_AGENT = "cxorcist/0.1 (+https://github.com/)"


def http_json(url: str, payload: dict | None = None, headers: dict | None = None, timeout: int = 30) -> dict:
    data = json.dumps(payload).encode() if payload is not None else None
    hdrs = {"Content-Type": "application/json", "User-Agent": USER_AGENT, **(headers or {})}
    req = urllib.request.Request(url, data=data, headers=hdrs)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        body = resp.read()
    return json.loads(body) if body else {}
