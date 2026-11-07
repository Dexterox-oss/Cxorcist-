from pathlib import Path

from cxorcist.ignore import make_matcher


def test_matcher_rules():
    m = make_matcher(["tests/", "*.min.js", "fixtures/sample", "secret.py"])
    assert m(Path("tests/test_a.py"))                 # directory name
    assert m(Path("src/tests/x.py"))                  # nested directory with that name
    assert m(Path("web/app.min.js"))                  # wildcard on file name
    assert m(Path("fixtures/sample/app.py"))          # path prefix
    assert m(Path("a/b/secret.py"))                   # file name anywhere
    assert not m(Path("src/app.py"))
    assert not m(Path("fixtures/other/app.py"))
