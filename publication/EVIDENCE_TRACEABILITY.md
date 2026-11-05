# Source-to-manuscript traceability (JSA-D-26-01018)

| Claim/figure | Source and evidence | Qualified interpretation |
|---|---|---|
| 34,419 physical CAN frames | `data/live_capture/exp_live_session.log`; `results/archived_claims_reconciled.json` | One physical campaign only |
| Attack occurrences A1,A2,A5,A6,A7,A8,A9: 30 each; A4: 1 | `results/archived_claims_reconciled.json`; `harness/strict_capture_audit.py` | Scripted events not independent sessions |
| 211/211 alert matches | `results/archived_claims_reconciled.json`; `results/archived_strict_frames_al.csv` | Reconstructed offline, not online IDS latency |
| A5 stale-sequence 30/30 | `results/archived_strict_audit.json`; `results/archived_claims_reconciled.json` | The literal replay fidelity check has FAIL status: A5 was crafted stale-sequence physical injection |
| 5,453 reconstructed alerts (Figs 5--6) | `results/archived_strict_frames_al.csv`; manuscript-generated Figs 5--6 | Alert count ≠ independent attack count |
| R1 FLOOD / R3 VEL_JUMP sweeps (Fig 7, Table 12) | `harness/sweep.py` -> `results/sweeps.json`; `src/tracer_ids.c`; `publication/render_figures_7_9.py` | 8 R1 / 13 R3 controlled settings; 30 synthetic events each, 9,849 benign frames |
| R6 timing (Fig 8a, Table 5) | `harness/sweep_validated.py` -> `results/validated_threshold_diagnostics.json` | 56 valid pairs, 7 missing companion checks; 8ms: 4 accepted / 4 late |
| R8 legitimate resumptions (Fig 8b, Table 10) | Same validated JSON and harness | 28 warnings /49 synthetic configurations; 5/7 at default 300ms |
| HMAC host sign / verify (Fig 9, Table 8) | `src/bench_hmac.c`; `results/today_final_audit/hmac_ubuntu_200k.json` | Summary-only, sign mean 0.914us, verify mean 0.862us; not embedded measurements |
| 14-ID whitelist; nine rule categories | `src/tracer_ids.h` and `src/tracer_ids.c` | Passive monitoring not receiver enforcement |
| Illustrative Wilson intervals | `harness/evaluate.py`; manuscript results | Independence assumptions not established; not deployment-level CIs |

The original baseline code and evidence files are retained byte-identical in this
release, with original documentation moved to `historical/` to avoid confusing
superseded claims with the final manuscript. Only publication-level scripts,
provenance documents, and test outputs have been added.
