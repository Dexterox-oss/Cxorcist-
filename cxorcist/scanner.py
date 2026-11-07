"""Cxorcist scanner: language-agnostic dependency discovery.

Walks a repo, parses dependency manifests and lockfiles for many ecosystems,
and returns a deduplicated list of Dependency records. Ecosystem names match
OSV.dev so the next stage can query vulnerabilities directly.

Stdlib only. Python 3.11+ (tomllib).
"""
from __future__ import annotations

import json
import re
import sys
import tomllib
import xml.etree.ElementTree as ET
from dataclasses import dataclass, asdict
from pathlib import Path

SKIP_DIRS = {
    ".git", "node_modules", "venv", ".venv", "env", "__pycache__", "vendor",
    "dist", "build", "target", ".tox", ".mypy_cache", ".idea", ".next",
}
EXACT = re.compile(r"^\d+(\.\d+)*([-+.][0-9A-Za-z.\-+]+)?$")


@dataclass(frozen=True)
class Dependency:
    ecosystem: str       # OSV ecosystem: PyPI, npm, Go, crates.io, RubyGems, Packagist, Maven, NuGet
    name: str
    version: str         # exact version, or "" if only a range was declared
    source_file: str     # path relative to scan root
    dev: bool = False


def _exact(v: str) -> str:
    """Return v if it is an exact version, else ''."""
    v = (v or "").strip().lstrip("=v ")
    return v if EXACT.match(v) else ""


def _read(p: Path) -> str:
    return p.read_text(encoding="utf-8", errors="ignore")


# ---------------- Python ----------------
_REQ = re.compile(r"^\s*([A-Za-z0-9_.\-]+)\s*(\[[^\]]*\])?\s*(.*)$")


def _pep508(spec: str):
    spec = spec.split(";")[0].split("#")[0].strip()
    m = _REQ.match(spec)
    if not m:
        return None
    name, _, rest = m.groups()
    pin = re.match(r"^===?\s*([^\s,]+)$", rest.strip())
    return name, _exact(pin.group(1)) if pin else ""


def parse_requirements(p: Path, root: Path):
    for line in _read(p).splitlines():
        line = line.strip()
        if not line or line.startswith(("-", "#", "git+", "http")):
            continue
        r = _pep508(line)
        if r:
            yield Dependency("PyPI", r[0], r[1], str(p.relative_to(root)))


def parse_pyproject(p: Path, root: Path):
    data = tomllib.loads(_read(p))
    rel = str(p.relative_to(root))
    for s in data.get("project", {}).get("dependencies", []):
        r = _pep508(s)
        if r:
            yield Dependency("PyPI", r[0], r[1], rel)
    for grp in data.get("project", {}).get("optional-dependencies", {}).values():
        for s in grp:
            r = _pep508(s)
            if r:
                yield Dependency("PyPI", r[0], r[1], rel, True)
    poetry = data.get("tool", {}).get("poetry", {})
    for sect, dev in (("dependencies", False), ("dev-dependencies", True)):
        for name, spec in poetry.get(sect, {}).items():
            if name.lower() == "python":
                continue
            v = spec if isinstance(spec, str) else spec.get("version", "")
            yield Dependency("PyPI", name, _exact(v), rel, dev)


def parse_toml_lock(p: Path, root: Path, ecosystem: str):
    """poetry.lock, uv.lock, Cargo.lock all use [[package]] name/version."""
    for pkg in tomllib.loads(_read(p)).get("package", []):
        if pkg.get("name") and pkg.get("version"):
            yield Dependency(ecosystem, pkg["name"], pkg["version"], str(p.relative_to(root)))


def parse_pipfile_lock(p: Path, root: Path):
    data = json.loads(_read(p))
    for sect, dev in (("default", False), ("develop", True)):
        for name, meta in data.get(sect, {}).items():
            yield Dependency("PyPI", name, _exact(meta.get("version", "")),
                             str(p.relative_to(root)), dev)


# ---------------- JavaScript ----------------
def parse_package_json(p: Path, root: Path):
    data = json.loads(_read(p))
    rel = str(p.relative_to(root))
    for sect, dev in (("dependencies", False), ("devDependencies", True),
                      ("optionalDependencies", False)):
        for name, v in data.get(sect, {}).items():
            yield Dependency("npm", name, _exact(v), rel, dev)


def parse_package_lock(p: Path, root: Path):
    data = json.loads(_read(p))
    rel = str(p.relative_to(root))
    for path, meta in data.get("packages", {}).items():     # lockfile v2/v3
        if not path:
            continue
        name = meta.get("name") or path.split("node_modules/")[-1]
        if meta.get("version"):
            yield Dependency("npm", name, meta["version"], rel, bool(meta.get("dev")))

    def walk(deps):                                          # lockfile v1
        for name, meta in (deps or {}).items():
            if meta.get("version"):
                yield Dependency("npm", name, meta["version"], rel, bool(meta.get("dev")))
            yield from walk(meta.get("dependencies"))
    if "packages" not in data:
        yield from walk(data.get("dependencies"))


def parse_yarn_lock(p: Path, root: Path):
    name = None
    for line in _read(p).splitlines():
        if line and not line.startswith((" ", "#")):
            m = re.match(r'^"?(@?[^@\s"]+)@', line)
            name = m.group(1) if m else None
        elif name:
            m = re.match(r'^\s+version:?\s+"?([^"\s]+)"?', line)
            if m:
                yield Dependency("npm", name, m.group(1), str(p.relative_to(root)))
                name = None


# ---------------- Go ----------------
def parse_go_mod(p: Path, root: Path):
    rel, in_block = str(p.relative_to(root)), False
    for line in _read(p).splitlines():
        s = line.split("//")[0].strip()
        if s.startswith("require ("):
            in_block = True
        elif in_block and s == ")":
            in_block = False
        else:
            m = re.match(r"^(?:require\s+)?(\S+)\s+v(\S+)$", s) if (in_block or s.startswith("require ")) else None
            if m:
                yield Dependency("Go", m.group(1), m.group(2), rel)


# ---------------- Rust ----------------
def parse_cargo_toml(p: Path, root: Path):
    data = tomllib.loads(_read(p))
    rel = str(p.relative_to(root))
    for sect, dev in (("dependencies", False), ("dev-dependencies", True),
                      ("build-dependencies", False)):
        for name, spec in data.get(sect, {}).items():
            v = spec if isinstance(spec, str) else spec.get("version", "")
            yield Dependency("crates.io", name, _exact(v), rel, dev)


# ---------------- Ruby / PHP ----------------
def parse_gemfile_lock(p: Path, root: Path):
    for m in re.finditer(r"^    (\S+) \(([^)\s,]+)\)$", _read(p), re.M):
        yield Dependency("RubyGems", m.group(1), m.group(2), str(p.relative_to(root)))


def parse_composer_lock(p: Path, root: Path):
    data = json.loads(_read(p))
    for sect, dev in (("packages", False), ("packages-dev", True)):
        for pkg in data.get(sect, []):
            yield Dependency("Packagist", pkg["name"], pkg.get("version", "").lstrip("v"),
                             str(p.relative_to(root)), dev)


def parse_composer_json(p: Path, root: Path):
    data = json.loads(_read(p))
    for sect, dev in (("require", False), ("require-dev", True)):
        for name, v in data.get(sect, {}).items():
            if name != "php" and not name.startswith("ext-"):
                yield Dependency("Packagist", name, _exact(v), str(p.relative_to(root)), dev)


# ---------------- JVM / .NET ----------------
def _strip_ns(root_el):
    for el in root_el.iter():
        el.tag = el.tag.split("}")[-1]
    return root_el


def parse_pom(p: Path, root: Path):
    tree = _strip_ns(ET.fromstring(_read(p)))
    pel = tree.find("properties")
    props = {c.tag: (c.text or "").strip() for c in pel} if pel is not None else {}
    for d in tree.iter("dependency"):
        g, a, v = (d.findtext(k, "").strip() for k in ("groupId", "artifactId", "version"))
        m = re.match(r"^\$\{(.+)\}$", v)
        if m:
            v = props.get(m.group(1), "")
        if g and a:
            yield Dependency("Maven", f"{g}:{a}", _exact(v), str(p.relative_to(root)),
                             d.findtext("scope", "") == "test")


def parse_gradle(p: Path, root: Path):
    pat = re.compile(r"""['"]([\w.\-]+):([\w.\-]+):([\w.\-]+)['"]""")
    for g, a, v in pat.findall(_read(p)):
        yield Dependency("Maven", f"{g}:{a}", _exact(v), str(p.relative_to(root)))


def parse_csproj(p: Path, root: Path):
    tree = _strip_ns(ET.fromstring(_read(p)))
    for r in tree.iter("PackageReference"):
        if r.get("Include"):
            yield Dependency("NuGet", r.get("Include"), _exact(r.get("Version", "")),
                             str(p.relative_to(root)))


# ---------------- Dispatch ----------------
def _parser_for(p: Path):
    n = p.name
    if re.match(r"^requirements.*\.txt$", n):  return parse_requirements
    if n == "pyproject.toml":                  return parse_pyproject
    if n in ("poetry.lock", "uv.lock"):        return lambda f, r: parse_toml_lock(f, r, "PyPI")
    if n == "Pipfile.lock":                    return parse_pipfile_lock
    if n == "package.json":                    return parse_package_json
    if n == "package-lock.json":               return parse_package_lock
    if n == "yarn.lock":                       return parse_yarn_lock
    if n == "go.mod":                          return parse_go_mod
    if n == "Cargo.toml":                      return parse_cargo_toml
    if n == "Cargo.lock":                      return lambda f, r: parse_toml_lock(f, r, "crates.io")
    if n == "Gemfile.lock":                    return parse_gemfile_lock
    if n == "composer.lock":                   return parse_composer_lock
    if n == "composer.json":                   return parse_composer_json
    if n == "pom.xml":                         return parse_pom
    if n in ("build.gradle", "build.gradle.kts"): return parse_gradle
    if n.endswith(".csproj"):                  return parse_csproj
    return None


def scan(root_path: str, ignore=None) -> dict:
    root = Path(root_path).resolve()
    found, errors, files = [], [], []
    for p in root.rglob("*"):
        if not p.is_file() or any(part in SKIP_DIRS for part in p.relative_to(root).parts):
            continue
        if ignore and ignore(p.relative_to(root)):
            continue
        parser = _parser_for(p)
        if not parser:
            continue
        files.append(str(p.relative_to(root)))
        try:
            found.extend(parser(p, root))
        except Exception as e:  # one bad manifest must never kill the scan
            errors.append({"file": str(p.relative_to(root)), "error": str(e)})

    # Dedupe; drop unpinned entries when a pinned one exists for the same package.
    pinned = {(d.ecosystem, d.name.lower()) for d in found if d.version}
    unique = {}
    for d in found:
        if not d.version and (d.ecosystem, d.name.lower()) in pinned:
            continue
        unique.setdefault((d.ecosystem, d.name.lower(), d.version), d)
    deps = sorted(unique.values(), key=lambda d: (d.ecosystem, d.name.lower(), d.version))

    ecosystems = {}
    for d in deps:
        ecosystems[d.ecosystem] = ecosystems.get(d.ecosystem, 0) + 1
    return {
        "root": str(root),
        "manifests_found": files,
        "ecosystems": ecosystems,
        "dependency_count": len(deps),
        "unpinned_count": sum(1 for d in deps if not d.version),
        "dependencies": [asdict(d) for d in deps],
        "errors": errors,
    }


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "."
    print(json.dumps(scan(target), indent=2))
