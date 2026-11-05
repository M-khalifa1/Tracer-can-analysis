# TRACER/JSA — source-and-evidence reproduction package (2026-11-04)

**Read this document first.** This archive accompanies the revised Journal of
Systems Architecture manuscript, *Experimental CAN Security Evaluation of a
Commercial Unmanned Ground Vehicle with Intrusion Detection and Authentication
Monitoring* (JSA-D-26-01018). It preserves the source and evidence of the
2026-10-28 baseline; original historical project notes are retained in
`historical/` solely for audit and may contain superseded/overstated claims.

## Provenance and correct interpretation

- **Physical evidence:** `data/live_capture/exp_live_session.log` has 34,419
  recorded CAN frames from **one** TRACER 2.0 physical campaign. Physical
  A1/A2/A5/A6/A7/A8/A9 comprise 30 scripted occurrences each; A4 is **one**
  bounded five-second high-rate session. This is *not* 211 independent trials.
- **Offline alert matching:** see `results/archived_claims_reconciled.json`.
  All 211 occurrences in that recording have matching IDS alerts after offline
  evaluation. There is **no** measured live IDS alert latency or prevention.
- **Physical A5 evidence limitation:** physical A5 was **crafted valid-MAC
  stale-sequence injection**, not verbatim authenticated-pair replay. The
  original `results/archived_strict_audit.json` retains status `FAIL` because
  the historical literal-replay fidelity expectation was not met. This result
  is *not changed or erased*. A corrected literal replay test was executed
  in software only. See `results/archived_claims_reconciled.json`.
- **Physical A4 evidence limitation:** a high-rate traffic session produced a
  matching FLOOD alert; controller denial of service was **not established**.
- **Benign interpretation:** 0 alerts among 10,414 frames outside attack
  windows in the archived capture under its exclusion rule, not a field FPR.
  Software mock and R8 warning incidence use different denominators.
- **Auth boundary:** the IDS passively checks companions for 0x111, 0x421,
  and 0x441. The original UGV controller does **not** enforce HMAC and may
  process an unauthorized command despite the IDS alert.
- **HMAC host benchmark:** `results/today_final_audit/hmac_ubuntu_200k.json`
  contains preserved summary values for 200,000 sign/verify iterations.
  CPU model/compiler identity and raw per-invocation samples are unavailable;
  the literal `FILL_ME` field is *historical evidence* and must not be
  silently replaced. The values are **not embedded/gateway latency data**.

## Building and reproducing

Requirements: Linux, gcc, make, Python 3, matplotlib, numpy and the test
packages listed in the original repository where applicable.

```bash
make                       # C detector + 8 regression tests
python -m pytest -q harness/test_dlc_parity.py harness/test_fasttrack.py
python harness/sweep.py     # fresh, deterministic R1/R3 results -> results/sweeps.json
python harness/sweep_validated.py    # R6/R8 results -> results/validated_threshold_diagnostics.json
python publication/render_figures_7_9.py --check-only
python publication/render_figures_7_9.py  # PDF vectors + 7680x4320 PNGs
```

The plotting script consumes the **recorded result files**. It does not
synthesize extra physical experiments or reconstruct raw benchmark samples.
The generated PDFs and PNGs are in `publication/figures/`. The final manuscript
LaTeX is distributed separately as a flat Elsevier-ready source archive.

## Where to find every reported result

See `publication/EVIDENCE_TRACEABILITY.md` for the claim-to-source table,
limitations, and archived-audit status. See `publication/PROVENANCE_LIMITATIONS.md`
for the remaining gaps. `publication/qa/` contains test and content-integrity
records. The original baseline binaries and old documentation have been
retained for traceability; when working on a new Linux host, **build the C
binaries from source** with `make` rather than trusting historical executables.

## Responsible use

`src/` includes an illustrative fixed experimental HMAC key for controlled
regression tests. It is not secure production key management. Do not attach
an untrusted CAN transmitter to an operational vehicle or run injection scripts
without explicit authorization and an appropriate controlled safety testbed.

## Archive separation

This **code/evidence ZIP** is a supplementary upload, distinct from the
**manuscript LaTeX ZIP** and the reviewer-response document. A Data/Code
Availability statement claiming attached supplementary code is accurate only
if this ZIP is actually uploaded to the journal submission.
