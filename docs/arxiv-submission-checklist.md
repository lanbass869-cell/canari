# arXiv submission checklist (Canari)

Status: source package prepared 2026-11-09. Submission itself must be done from
the author's arXiv account (requires login + category endorsement for cs.CR or cs.SE).

## Package contents
- `arxiv/main.tex` (single-file LaTeX, bibliography inline in thebibliography) - no external .bib needed
- Compile command: `pdflatex main.tex` twice (no bibtex)

## Pre-submission checks
- [x] Numbers consistent with the live store (530 bundles / 258 components / 100% schema+sig / 190 chains)
- [x] Related-work table claims verified against source code (docs/research/competitor_deep_research_v5_20261109.md)
- [x] Honest limitations section lists scan depth zero, single signer, PyPI blank, registry count floor, npm v0.1 unverifiable
- [ ] PDF compilation on a host with a TeX toolchain (this host has none; main.tex is environment-balanced)
- [ ] Author name/affiliation filled in (currently "Canari Contributors")
- [ ] Category: cs.CR (primary), cs.SE (cross-list)
- [ ] License: arXiv non-exclusive license (default) or CC-BY-4.0

## Metadata draft
- Title: Verdict Attestations: A Cross-Registry, Offline-Verifiable Ledger for AI Agent Component Supply Chains
- Comments: 13 pages, 2 tables; code and data at github.com/lanbass869-cell/canari
- Abstract: as in main.tex (no changes needed)

## After submission
- Record the arXiv ID in README.md and docs/nlnet-application-20261108.md
