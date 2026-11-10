# -*- coding: utf-8 -*-
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def test_version_key_orders_numerically_not_lexically():
    from canari.npm_enum import _version_key
    assert _version_key("1.2.3") < _version_key("1.10.0")
    assert _version_key("2.0.0") > _version_key("1.99.99")
    assert _version_key("1.0.0") == _version_key("1.0.0")


def test_version_key_handles_prerelease_and_junk():
    from canari.npm_enum import _version_key
    # 1.0.0-rc1 -> (1,0,0,1); the numeric core still dominates
    assert _version_key("1.0.0-rc1")[:3] == (1, 0, 0)
    assert _version_key("") == (-1,)
    assert _version_key(None) == (-1,)
    assert _version_key("no-digits") == (-1,)


def test_version_key_caps_at_six_segments():
    from canari.npm_enum import _version_key
    assert len(_version_key("1.2.3.4.5.6.7.8")) == 6


def test_propagate_revocation_same_author():
    from canari.npm_enum import propagate_revocation
    comps = [
        {"name": "evil-pkg", "maintainers": ["badguy"]},
        {"name": "other-pkg", "maintainers": ["badguy"]},
        {"name": "unrelated", "maintainers": ["someoneelse"]},
    ]
    rel = propagate_revocation("evil-pkg", "badguy", comps)
    names = {r["name"]: r["relation"] for r in rel}
    assert names.get("other-pkg") == "same-author"
    assert "evil-pkg" not in names          # never self
    assert "unrelated" not in names


def test_propagate_revocation_name_variant():
    from canari.npm_enum import propagate_revocation
    comps = [{"name": "lodash-utils", "maintainers": []}]
    rel = propagate_revocation("lodash-util", None, comps)
    assert rel and rel[0]["relation"] == "name-variant"


def test_propagate_revocation_short_name_never_matches():
    from canari.npm_enum import propagate_revocation
    comps = [{"name": "abcd", "maintainers": []}]
    # len(revoked) <= 4 disables the similarity path entirely
    assert propagate_revocation("abce", None, comps) == []
