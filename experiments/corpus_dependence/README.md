# Corpus dependence of name-similarity (typosquat) verdicts

**Question.** A name-similarity check answers *"is this package close to some
other package?"* — a property of a **set**, not of one package. So: if the same
package is scanned against a smaller and a larger set of names, can its verdict
change without the package changing at all?

**Answer measured here: yes, for 13 of 60 sampled packages (21.7%).**

## Inputs

`names.txt` — 620 names beginning with `mcp-server-`, extracted from the public
PyPI simple index on 2026-11-16. This is the whole "MCP-relevant" namespace as
visible through that index, not a sample.

Similarity: Damerau-Levenshtein over names with hyphens removed; a pair counts as
similar at edit distance ≤ 1 for names shorter than 8 characters and ≤ 2
otherwise (short-name leniency). This mirrors `canari/typosquat.py`, the rule the
scanner actually used.

## Result 1 — the same package flips verdict when the corpus grows

60 targets drawn with `seed=20261116`. Corpus A = the 60 targets themselves.
Corpus B = all 620 names.

| | count |
|---|---|
| flagged in **both** corpora | 8 |
| flagged **only** in the full corpus | **13** |
| flagged **only** in the small corpus | 0 |
| flagged in neither | 39 |
| **flip rate over all 60 targets** | **21.7 %** |

Zero flips in the reverse direction is expected and worth stating: adding names
can only add neighbours, never remove them. So the defect is monotone — **a
scanner that loads more of the registry reports strictly more typosquatting**,
regardless of whether any package changed.

Examples that become "typosquatting" only once the full corpus is loaded:
`mcp-server-aistudio`, `mcp-server-b24`, `mcp-server-deepresearch-thy`,
`mcp-server-demo-9`, `mcp-server-docs`.

## Result 2 — the flagged fraction grows with corpus size

Five random samples per size:

| corpus size n | flagged fraction (mean ± sd) | close pairs (mean) | pairs / n² |
|---|---|---|---|
| 50 | 0.112 ± 0.020 | 4.4 | 0.00176 |
| 100 | 0.176 ± 0.048 | 18.4 | 0.00184 |
| 200 | 0.224 ± 0.033 | 83.8 | 0.00210 |
| 300 | 0.239 ± 0.025 | 150.4 | 0.00167 |
| 400 | 0.291 ± 0.015 | 241.0 | 0.00151 |
| 500 | 0.305 ± 0.009 | 375.2 | 0.00150 |
| **620** | **0.337** ± 0.000 | **573** | **0.00149** |

`pairs / n²` stays between 0.0015 and 0.0021 across a 12× range of n — close
pairs grow as Θ(n²), which is the birthday-problem shape. The *fraction* of
names flagged therefore grows with n, from 11 % to 34 %.

## Result 3 — the verdict is also threshold-sensitive

At n = 620:

| max distance | flagged names | flagged fraction | close pairs |
|---|---|---|---|
| 1 | 64 | 10.3 % | 51 |
| 2 | 209 | 33.7 % | 573 |
| 3 | 336 | 54.2 % | 3385 |

Moving the threshold by one character triples the number of accusations.

## What this means

A verdict like "`mcp-server-x` is probably a typosquat of `mcp-server-y`" is not
a fact about `mcp-server-x`. It is a fact about the pair, discovered by comparing
against whatever set the scanner loaded. Two scanners that both implemented the
algorithm correctly, on the same package, on the same day, can publish different
verdicts — and neither is wrong.

Consequences:

- A verdict record that does not commit to its **comparison corpus** cannot be
  reproduced by anyone else. Our attestations commit to the registry entry
  (`sources.registry_entry`) but **not** to the name set used for comparison —
  so this class of finding is currently unreproducible by design.
- "Scan more of the registry" is not a neutral improvement: it mechanically
  increases the reported typosquat rate.
- Cross-registry or cross-time comparisons of typosquat rates are meaningless
  unless the corpora are identical.

## Fix that landed because of this

Attestations now carry the name set they were computed against, on the L2.6 row
and in `evidence_refs`:

```json
"comparison_corpus": {
  "registry": "pypi",
  "kind": "name-set",
  "size": 620,
  "digest": "sha256:…",
  "canonicalization": "sha256(utf-8, casefolded names sorted asc, LF-joined, trailing LF)",
  "as_of": "2026-11-16T05:31:35Z"
}
```

plus a one-line `corpus:pypi:sha256:…:n=620` entry in `evidence_refs`. Two
attestations that disagree on a typosquat verdict can now be told apart by
whether they compared against the same corpus, instead of looking like a
contradiction. Drift is unaffected: `canari/drift.py` compares chain id -> verdict
only, so the corpus commitment does not register as a "silent change" on every
run.

## Reproduce

```
python run.py        # deterministic; writes results.json
```

Requires `canari` importable (the rule lives in `canari/typosquat.py`).

## Limitations (stated, not hidden)

- One namespace (`mcp-server-*`, 620 names). Registry-wide behaviour may differ,
  though the Θ(n²) mechanism does not depend on the namespace.
- Similarity is the scanner's own historical rule, not a tuned detector. That is
  the point — this is what the shipped rule does.
- No ground truth for "real typosquat", so this measures **verdict stability**,
  not accuracy. A stable-but-wrong detector would score perfectly here.
