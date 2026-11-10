"""typosquat.py - H3: Typosquatting detection.

Checks if a package name is unusually similar to a known trusted package.
Uses Damerau-Levenshtein distance (supports adjacent transposition) + compact name comparison.

trustcheck reference: malicious.py _typosquatting_findings L758-803
"""
from difflib import SequenceMatcher


def _damerau_levenshtein(left, right):
    """Damerau-Levenshtein edit distance (supports adjacent transposition)."""
    if left == right:
        return 0
    if not left:
        return len(right)
    if not right:
        return len(left)
    matrix = [[0] * (len(right) + 1) for _ in range(len(left) + 1)]
    for i in range(len(left) + 1):
        matrix[i][0] = i
    for j in range(len(right) + 1):
        matrix[0][j] = j
    for i in range(1, len(left) + 1):
        for j in range(1, len(right) + 1):
            substitution = 0 if left[i-1] == right[j-1] else 1
            matrix[i][j] = min(
                matrix[i-1][j] + 1,
                matrix[i][j-1] + 1,
                matrix[i-1][j-1] + substitution,
            )
            if i > 1 and j > 1 and left[i-1] == right[j-2] and left[i-2] == right[j-1]:
                matrix[i][j] = min(matrix[i][j], matrix[i-2][j-2] + substitution)
    return matrix[-1][-1]


def check_typosquatting(project, trusted_names):
    """Check if project is a typosquatting candidate.

    Args:
        project: package name to check
        trusted_names: set of known-good package names

    Returns:
        dict with id/verdict/tool/evidence_ref, or None if clean.
    """
    if not project or not trusted_names:
        return None
    import unicodedata

    def _fold(s):
        # NFKC folds fullwidth/compatibility forms to ASCII (ｍｃｐ -> mcp)
        return unicodedata.normalize("NFKC", s)

    project = _fold(project)
    trusted_names = {_fold(t) for t in trusted_names}

    def _family_tails(a_orig, b_orig):
        """Strip the shared hyphen-boundary prefix (family scope). Comparing within
        a big family (mcp-server-*) on full names makes everything look alike, but
        stripping a partial-word prefix would eat the typo itself (fecth/fetch).
        Only complete hyphen-delimited leading segments are stripped."""
        a, b = a_orig.casefold(), b_orig.casefold()
        cut = 0
        idx = 0
        while idx < min(len(a), len(b)) and a[idx] == b[idx]:
            if a[idx] == "-":
                cut = idx + 1
            idx += 1
        if cut >= 4:
            return a[cut:], b[cut:]
        return a, b

    candidate = project.replace("-", "").casefold()
    matches = []
    for trusted in trusted_names:
        if trusted == project:
            continue
        ta, tb = _family_tails(project, trusted)
        if not ta or not tb:
            continue  # one is a scope prefix of the other: not a typosquat
        # wrapper pattern: one distinctive tail is a suffix of the other by 2+
        # chars (aistudio vs 3daistudio). A one-char prefix extension is a typo
        # (dateutil vs dateutils), so it stays in scope.
        if (tb.endswith(ta) and len(tb) - len(ta) >= 2) or (ta.endswith(tb) and len(ta) - len(tb) >= 2):
            continue
        a, b = ta.replace("-", ""), tb.replace("-", "")
        distance = _damerau_levenshtein(a, b)
        maximum = max(len(a), len(b), 1)
        similarity = 1.0 - distance / maximum
        threshold = 1 if maximum < 8 else 2
        if distance <= threshold and similarity >= 0.72:
            matches.append((distance, similarity, trusted))
    if not matches:
        return None
    distance, similarity, trusted = min(matches, key=lambda x: (x[0], -x[1], x[2]))
    score = 45 if distance == 1 else 32
    severity = "high" if distance == 1 else "medium"
    return {
        "id": "L2.6_TYPOSQUATTING",
        "verdict": "pass",
        "tool": "canari-typosquat/0.1",
        "evidence_ref": "finding: typosquatting_name_similarity - candidate=%s trusted=%s distance=%d similarity=%.3f score=%d severity=%s" % (
            project, trusted, distance, similarity, score, severity),
    }
