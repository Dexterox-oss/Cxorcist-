import sys
from pathlib import Path

from conftest import FIXTURE
from cxorcist.__main__ import main


def test_llm_flag_without_key_prints_clear_error(monkeypatch, capsys):
    monkeypatch.delenv("GROQ_API_KEY", raising=False)
    assert main(["scan", FIXTURE, "--llm", "--offline"]) == 1
    assert "GROQ_API_KEY" in capsys.readouterr().err


def test_failed_webhook_does_not_crash_the_scan(capsys):
    rc = main(["scan", FIXTURE, "--offline", "--cache", "", "--alert-url", "http://127.0.0.1:9/hook"])
    assert rc == 0
    assert "could not post to webhook" in capsys.readouterr().err


def test_fail_on_exit_code():
    assert main(["scan", FIXTURE, "--offline", "--cache", "", "--fail-on", "high"]) == 2
    assert main(["scan", FIXTURE, "--offline", "--cache", "", "--ignore", "app.py", "--ignore", "broken.py",
                 "--ignore", "script.js", "--fail-on", "high"]) == 0
