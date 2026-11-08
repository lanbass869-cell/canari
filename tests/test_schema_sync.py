# -*- coding: utf-8 -*-
"""Schema sync guard (MemTether dual_repo_guard pattern).

The bundled schemas/attestation-v0.1.json MUST stay byte-identical to the
private handover repo copy. Semantic changes go through the WorkBuddy
review line (HANDOVER section 5); if the source moves, update SOURCE_PATH.
"""
import filecmp
import os

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BUNDLED = os.path.join(HERE, "schemas", "attestation-v0.1.json")
# update if the handover repo moves; missing source = SKIP not PASS
SOURCE_CANDIDATES = [
    r"E:\Temp\tbdig\feiyu-quanti\docs\canari\attestation-v0.1.schema.json",
]


def test_bundled_schema_exists():
    assert os.path.isfile(BUNDLED), "bundled schema missing"


def test_bundled_matches_source():
    srcs = [s for s in SOURCE_CANDIDATES if os.path.isfile(s)]
    if not srcs:
        import pytest
        pytest.skip("handover repo not present on this machine")
    import filecmp
    for s in srcs:
        if filecmp.cmp(BUNDLED, s, shallow=False):
            return
    raise AssertionError(
        "schema drift: bundled %s differs from all known sources %s - "
        "semantic changes require WorkBuddy review (HANDOVER section 5)"
        % (BUNDLED, srcs))
