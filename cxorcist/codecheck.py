"""
Static bug/error/secret checks. Heuristic by design: this finds likely problems
for a human (or the LLM triage step) to review. It is not a full SAST tool.
Secret values are redacted at the source so they never reach reports or the LLM.
"""
from __future__ import annotations

import ast
import json
import re
import tomllib
from pathlib import Path

from .models import Finding
from .scanner import SKIP_DIRS

MAX_BYTES = 1_000_000
PY_EXT = {".py"}
JS_EXT = {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"}
SECRET_EXT = PY_EXT | JS_EXT | {".json", ".toml", ".yml", ".yaml", ".cfg", ".ini", ".sh", ".properties",
                                ".rb", ".go", ".java", ".php", ".rs", ".cs", ".env"}

JS_RULES = [
    ("js-eval", re.compile(r"\beval\s*\("), "Use of eval() allows arbitrary code execution", "high"),
    ("js-new-function", re.compile(r"\bnew\s+Function\s*\("), "new Function() evaluates strings as code", "high"),
    ("js-innerhtml", re.compile(r"\.innerHTML\s*="), "Assigning innerHTML can enable XSS", "medium"),
    ("js-document-write", re.compile(r"\bdocument\.write\s*\("), "document.write can enable XSS", "medium"),
    ("js-dangerous-html", re.compile(r"dangerouslySetInnerHTML"), "dangerouslySetInnerHTML can enable XSS", "medium"),
]

_PLACEHOLDER = re.compile(r"(?i)example|your[_-]|xxx|changeme|placeholder|<|\$\{|\{\{|env\b|none|null|test")
SECRET_RULES = [
    ("secret-private-key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"), "Private key committed to the repo", "critical", 0),
    ("secret-aws-key", re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "AWS access key ID in source", "critical", 0),
    ("secret-github-token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"), "GitHub token in source", "critical", 0),
    ("secret-groq-key", re.compile(r"\bgsk_[A-Za-z0-9]{20,}\b"), "Groq API key in source", "critical", 0),
    ("secret-slack-token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}"), "Slack token in source", "high", 0),
    ("secret-api-key", re.compile(r"\bsk-[A-Za-z0-9_\-]{20,}"), "API key (sk-...) in source", "high", 0),
    ("secret-hardcoded", re.compile(r"""(?i)\b(?:api[_-]?key|secret|token|passwd|password)\b\s*[:=]\s*['"]([^'"\s]{8,})['"]"""),
     "Hard-coded credential", "high", 1),
]


def _dotted(node: ast.AST) -> str:
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
        return ".".join(reversed(parts))
    return ""


def _is_const(node: ast.AST, value) -> bool:
    return isinstance(node, ast.Constant) and node.value is value


class _PyVisitor(ast.NodeVisitor):
    def __init__(self, rel: str, lines: list[str], out: list[Finding]):
        self.rel, self.lines, self.out = rel, lines, out

    def add(self, node: ast.AST, rule: str, title: str, severity: str) -> None:
        ln = getattr(node, "lineno", 0)
        snippet = self.lines[ln - 1].strip()[:160] if 0 < ln <= len(self.lines) else ""
        self.out.append(Finding("code_issue", rule, title, severity, "rule", file=self.rel, line=ln,
                                snippet=snippet, tier="review", tier_reason="Code issues need a human review."))

    def visit_Call(self, node: ast.Call) -> None:
        name = _dotted(node.func)
        kws = {k.arg: k.value for k in node.keywords if k.arg}
        if name in ("eval", "exec"):
            self.add(node, f"py-{name}", f"Use of {name}() allows arbitrary code execution", "high")
        elif name == "os.system":
            self.add(node, "py-os-system", "os.system() runs a shell command", "medium")
        elif name.startswith("subprocess.") and _is_const(kws.get("shell"), True):
            self.add(node, "py-shell-true", "subprocess with shell=True risks command injection", "high")
        elif name in ("pickle.load", "pickle.loads"):
            self.add(node, "py-pickle", "pickle can execute code when loading untrusted data", "high")
        elif name == "yaml.load" and "Loader" not in kws and len(node.args) < 2:
            self.add(node, "py-yaml-load", "yaml.load without a safe Loader can execute code", "medium")
        elif name.startswith("requests.") and _is_const(kws.get("verify"), False):
            self.add(node, "py-tls-verify-off", "TLS verification disabled (verify=False)", "medium")
        elif name in ("hashlib.md5", "hashlib.sha1"):
            self.add(node, "py-weak-hash", f"{name} is a weak hash for security use", "low")
        elif name.endswith(".run") and _is_const(kws.get("debug"), True):
            self.add(node, "py-debug-true", "Debug mode enabled in app.run()", "medium")
        self.generic_visit(node)

    def visit_ExceptHandler(self, node: ast.ExceptHandler) -> None:
        if node.type is None:
            self.add(node, "py-bare-except", "Bare except hides errors", "low")
        elif len(node.body) == 1 and isinstance(node.body[0], ast.Pass):
            self.add(node, "py-swallowed-exception", "Exception caught and silently ignored", "low")
        self.generic_visit(node)

    def _check_defaults(self, node) -> None:
        for d in list(node.args.defaults) + [d for d in node.args.kw_defaults if d]:
            if isinstance(d, (ast.List, ast.Dict, ast.Set)) or (
                isinstance(d, ast.Call) and _dotted(d.func) in ("list", "dict", "set")):
                self.add(d, "py-mutable-default", f"Mutable default argument in {node.name}()", "low")
        self.generic_visit(node)

    visit_FunctionDef = _check_defaults
    visit_AsyncFunctionDef = _check_defaults


def check_python(rel: str, text: str) -> list[Finding]:
    out: list[Finding] = []
    try:
        tree = ast.parse(text)
    except SyntaxError as e:
        return [Finding("code_issue", "py-syntax-error", f"Python syntax error: {e.msg}", "high", "rule",
                        file=rel, line=e.lineno or 0, tier="review", tier_reason="File cannot be parsed.")]
    _PyVisitor(rel, text.splitlines(), out).visit(tree)
    return out


def check_js(rel: str, text: str) -> list[Finding]:
    out = []
    for i, line in enumerate(text.splitlines(), 1):
        if line.lstrip().startswith(("//", "*", "/*")):
            continue
        for rule, rx, title, sev in JS_RULES:
            if rx.search(line):
                out.append(Finding("code_issue", rule, title, sev, "rule", file=rel, line=i, snippet=line.strip()[:160],
                                   tier="review", tier_reason="Code issues need a human review."))
    return out


def check_secrets(rel: str, text: str) -> list[Finding]:
    out = []
    for i, line in enumerate(text.splitlines(), 1):
        for rule, rx, title, sev, grp in SECRET_RULES:
            m = rx.search(line)
            if not m:
                continue
            if grp and _PLACEHOLDER.search(m.group(grp)):
                continue
            span = m.span(grp) if grp else m.span()
            redacted = (line[:span[0]] + "[REDACTED]" + line[span[1]:]).strip()[:160]
            out.append(Finding("code_issue", rule, title, sev, "rule", file=rel, line=i, snippet=redacted,
                               tier="escalate", tier_reason="Exposed secret: rotate it and remove from history."))
            break  # one secret finding per line
    return out


def check_config(rel: str, path: Path, text: str) -> list[Finding]:
    name = path.name.lower()
    try:
        if path.suffix == ".json" and not name.startswith(("tsconfig", "jsconfig", ".eslintrc")):
            json.loads(text)
        elif path.suffix == ".toml":
            tomllib.loads(text)
    except json.JSONDecodeError as e:
        return [Finding("code_issue", "invalid-json", f"Invalid JSON: {e.msg}", "medium", "rule", file=rel,
                        line=e.lineno, tier="review", tier_reason="Config cannot be parsed.")]
    except tomllib.TOMLDecodeError as e:
        return [Finding("code_issue", "invalid-toml", f"Invalid TOML: {e}", "medium", "rule", file=rel,
                        tier="review", tier_reason="Config cannot be parsed.")]
    return []


def _is_env_file(p: Path) -> bool:
    return p.name == ".env" or (p.name.startswith(".env.") and not p.name.endswith((".example", ".sample")))


def check_repo(root_path: str, ignore=None) -> tuple[list[Finding], list[dict]]:
    root = Path(root_path).resolve()
    findings: list[Finding] = []
    errors: list[dict] = []
    for p in root.rglob("*"):
        rel_parts = p.relative_to(root).parts
        if not p.is_file() or any(part in SKIP_DIRS for part in rel_parts):
            continue
        if ignore and ignore(p.relative_to(root)):
            continue
        suffix = p.suffix.lower()
        env_file = _is_env_file(p)
        if suffix not in SECRET_EXT and suffix != ".toml" and not env_file:
            continue
        try:
            if p.stat().st_size > MAX_BYTES:
                continue
            text = p.read_text(encoding="utf-8", errors="ignore")
            rel = str(p.relative_to(root))
            if suffix in PY_EXT:
                findings += check_python(rel, text)
            elif suffix in JS_EXT:
                findings += check_js(rel, text)
            findings += check_config(rel, p, text)
            findings += check_secrets(rel, text)
        except Exception as e:  # one unreadable file must never stop a scan
            errors.append({"file": str(p.relative_to(root)), "error": str(e)})
    return findings, errors
