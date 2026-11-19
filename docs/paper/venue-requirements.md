# FSE 2027 IVR - verified submission requirements (2026-11-19)

Source: https://conf.researchr.org/track/fse-2027/fse-2027-ideas-visions-and-reflections
(fetched and read 2026-11-19; quotes below are verbatim from that page).

## Hard requirements

| item | requirement |
|---|---|
| page limit | "must not exceed four pages (not including a one-page bibliography)" |
| review model | "FSE-IVR will employ the same double blind review process as the main research track." / "Submissions must not reveal authors' identities" |
| format | main-track CfP specifies \documentclass[acmsmall,screen,review,anonymous]{acmart} |
| evaluation | "Evaluation results are not required for FSE-IVR papers." (verbatim) |
| deadline | February 12, 2027, 23:59:59 AoE (UTC-12h) |
| notification | March 12, 2027 |
| camera-ready | April 12, 2027 |
| APC | USD 500 (ACM/SIG members) / USD 750 (non-members) for calendar year 2027 |

## Consequences for the draft

1. **Double-blind**: the draft must not name the project, link to a repository, or cite our
   own prior work in a self-identifying way. `review,anonymous` handles the author block;
   the body must also be scrubbed.
2. **4 pages of body + 1 page of references**: the Markdown draft is ~1,700 words; it fits,
   but the tables and section 7 will need tightening.
3. **Evaluation not required** is explicitly allowed, which is what lets a measurement
   paper of this shape in - but it does not excuse a weak claim; the mock review stands.
4. **APC is real money**: USD 500-750 if accepted. Flag before camera-ready.

## Local toolchain status

No pdflatex, xelatex, or latexmk on this machine (checked 2026-11-19). The .tex source can
be written but **cannot be compiled here**; it needs Overleaf or a TeX install. Do not claim
"compiles" until a real compile has been run.
