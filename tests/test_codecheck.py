from conftest import FIXTURE
from cxorcist.codecheck import check_repo


def rules():
    findings, errors = check_repo(FIXTURE)
    return findings, {f.rule for f in findings}


def test_finds_expected_issues():
    _, found = rules()
    expected = {"py-eval", "py-shell-true", "py-os-system", "py-pickle", "py-yaml-load", "py-tls-verify-off",
                "py-weak-hash", "py-bare-except", "py-mutable-default", "py-debug-true", "py-syntax-error",
                "invalid-json", "js-eval", "js-innerhtml", "secret-hardcoded"}
    assert expected <= found, expected - found


def test_secret_values_are_never_stored():
    findings, _ = rules()
    for f in findings:
        assert "hunter2hunter2" not in f.snippet
    secret = next(f for f in findings if f.rule == "secret-hardcoded")
    assert "[REDACTED]" in secret.snippet


def test_placeholders_are_not_flagged(tmp_path):
    (tmp_path / "a.py").write_text('api_key = "your_api_key_here"\n')
    findings, _ = check_repo(str(tmp_path))
    assert not findings
