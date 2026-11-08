import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from canari.npm_enum import propagate_revocation


class TestPropagateRevocation:
    def test_same_author(self):
        components = [
            {"name": "evil-pkg", "maintainers": ["attacker"]},
            {"name": "other-pkg", "maintainers": ["attacker"]},
            {"name": "safe-pkg", "maintainers": ["someone-else"]},
        ]
        result = propagate_revocation("evil-pkg", "attacker", components)
        names = [r["name"] for r in result]
        assert "other-pkg" in names
        assert "safe-pkg" not in names

    def test_name_variant(self):
        components = [
            {"name": "postmark-mcp", "maintainers": []},
            {"name": "postmark-mcp2", "maintainers": []},
            {"name": "unrelated-thing", "maintainers": []},
        ]
        result = propagate_revocation("postmark-mcp", "", components)
        names = [r["name"] for r in result]
        assert "postmark-mcp2" in names
        assert "unrelated-thing" not in names

    def test_no_self_match(self):
        assert propagate_revocation("pkg-a", "", [{"name": "pkg-a"}]) == []

    def test_empty_components(self):
        assert propagate_revocation("pkg-a", "", []) == []

    def test_relation_field(self):
        result = propagate_revocation(
            "pkg-a", "bob",
            [{"name": "pkg-b", "maintainers": ["bob"]}])
        assert result[0]["relation"] == "same-author"
