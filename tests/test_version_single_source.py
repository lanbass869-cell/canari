# -*- coding: utf-8 -*-
"""The package must have exactly one source of truth for its version.

found 2026-11-19: the published canari_mcp-0.1.4 wheel had

    METADATA Version: 0.1.4
    canari/__init__.py __version__ = "0.1.3"

so the MCP server answered "0.1.3" to a client that had installed 0.1.4. Two
hand-maintained copies of a version number drift exactly like any other
duplicated state; the fix is to delete one of them, not to keep them in sync by
discipline.

pyproject now declares `dynamic = ["version"]` with
`[tool.setuptools.dynamic] version = {attr = "canari.__version__"}`, and these
tests pin both directions.
"""
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import canari  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _pyproject():
    with open(os.path.join(ROOT, "pyproject.toml"), encoding="utf-8") as f:
        return f.read()


def test_pyproject_does_not_hardcode_a_version():
    text = _pyproject()
    assert 'dynamic = ["version"]' in text, (
        "a literal version in [project] is a second source of truth and will drift")
    assert not re.search(r'^version\s*=\s*"', text, re.M), (
        "found a hardcoded version in pyproject.toml:\n"
        + "\n".join(l for l in text.splitlines() if l.startswith("version")))


def test_pyproject_reads_the_version_from_the_package():
    text = _pyproject()
    assert "[tool.setuptools.dynamic]" in text
    assert 'version = {attr = "canari.__version__"}' in text, (
        "the dynamic version must resolve to the package's own __version__")


def test_version_is_a_plain_dotted_number():
    v = canari.__version__
    assert re.match(r"^\d+\.\d+\.\d+", v), "unexpected version shape: %r" % (v,)


def test_mcp_server_reports_the_package_version():
    """A client asking the server its version must get the installed one."""
    from canari import mcp_server
    assert mcp_server.SERVER_INFO["version"] == canari.__version__, (
        "MCP server advertises %r but the package is %r"
        % (mcp_server.SERVER_INFO["version"], canari.__version__))
