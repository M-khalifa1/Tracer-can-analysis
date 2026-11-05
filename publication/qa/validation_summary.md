# Bounded final verification, 2026-11-04

- Frozen 2026-10-28 source/evidence baseline: 100/100 original files
  verified byte-identical, including files relocated to `historical/`.
- Source C build and test: `make -B`: 8 passed, 0 failed.
- Targeted Python regression: `python -m pytest -q harness/test_dlc_parity.py harness/test_fasttrack.py`: 7 passed.
- `python harness/sweep.py` fresh output SHA256: `092d2c4b79351169a59122399e6ff0afa4cc0eb3dbe3068672e6b09eeb092a52` (matches preserved sweeps.json).
- `python harness/sweep_validated.py` fresh output SHA256: `210c803a2da91f91850dbd2f3ec9ba8b0354eda216eac56c8372462f88fea0ad` (matches preserved validated_threshold_diagnostics.json).
- Fig.7/8/9 generated from input JSON as PDF vectors and 7680x4320 PNGs.
- `elsarticle` paper: 39-page marked and 39-page clean PDF compiled with pdflatex/BibTeX, 35 references; no undefined citations.
- Reviewer letter: 37-page DOCX-based PDF, standalone LaTeX compiled; all references to the new plots and Table 12 reconciled.

Outstanding caveats: physical A5 original literal replay expectation `FAIL` remains recorded and qualified; HMAC host CPU/compiler and original per-invocation samples cannot be recovered from available evidence; no extra physical experiments or embedded benchmark were performed. No claim of deployed real-time prevention is made.
