"""Ignore rules: a .cxorcistignore file in the scanned folder, plus --ignore patterns."""
from __future__ import annotations

import fnmatch
from pathlib import Path
from typing import Callable

IGNORE_FILE = ".cxorcistignore"


def load_patterns(root: Path, extra: list[str] | None = None) -> list[str]:
    patterns: list[str] = []
    f = root / IGNORE_FILE
    if f.is_file():
        for line in f.read_text(encoding="utf-8", errors="ignore").splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                patterns.append(line)
    patterns += [p.strip() for p in (extra or []) if p and p.strip()]
    return patterns


def make_matcher(patterns: list[str]) -> Callable[[Path], bool]:
    """Return is_ignored(relative_path). A pattern matches a full path, a path prefix,
    or any single file/folder name in the path (e.g. 'tests', '*.min.js', 'fixtures/sample')."""
    def is_ignored(rel: Path) -> bool:
        rel_s = rel.as_posix()
        for pat in patterns:
            p = pat.rstrip("/")
            if not p:
                continue
            if fnmatch.fnmatch(rel_s, p) or rel_s.startswith(p + "/"):
                return True
            if any(fnmatch.fnmatch(part, p) for part in rel.parts):
                return True
        return False
    return is_ignored
