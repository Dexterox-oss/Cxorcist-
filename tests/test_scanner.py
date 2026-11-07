import json

from cxorcist.scanner import scan


def test_multi_language_manifests(tmp_path):
    (tmp_path / "requirements.txt").write_text("requests==2.25.0\nflask>=2.0\n")
    (tmp_path / "package.json").write_text(json.dumps({"dependencies": {"lodash": "^4.17.20"}}))
    (tmp_path / "package-lock.json").write_text(json.dumps(
        {"lockfileVersion": 3, "packages": {"": {}, "node_modules/lodash": {"version": "4.17.20"}}}))
    (tmp_path / "go.mod").write_text("module x\nrequire (\n\tgithub.com/gin-gonic/gin v1.7.0\n)\n")
    (tmp_path / "Cargo.toml").write_text('[dependencies]\nserde = "1.0.130"\n')
    r = scan(str(tmp_path))
    got = {(d["ecosystem"], d["name"], d["version"]) for d in r["dependencies"]}
    assert ("PyPI", "requests", "2.25.0") in got
    assert ("PyPI", "flask", "") in got                  # range only -> unpinned
    assert ("npm", "lodash", "4.17.20") in got           # lockfile wins over range
    assert ("npm", "lodash", "") not in got
    assert ("Go", "github.com/gin-gonic/gin", "1.7.0") in got
    assert ("crates.io", "serde", "1.0.130") in got


def test_skips_vendor_dirs_and_survives_bad_manifest(tmp_path):
    (tmp_path / "node_modules" / "x").mkdir(parents=True)
    (tmp_path / "node_modules" / "x" / "package.json").write_text('{"dependencies":{"evil":"1.0.0"}}')
    (tmp_path / "package.json").write_text("{bad json")
    r = scan(str(tmp_path))
    assert r["dependency_count"] == 0
    assert len(r["errors"]) == 1
