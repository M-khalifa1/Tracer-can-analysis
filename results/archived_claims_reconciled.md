# Archived TRACER physical capture — independent claim reconciliation

**NOT a full strict PASS.** QUALIFIED_ARCHIVED_EVIDENCE.

- Raw capture SHA-256: `5f7e2ca1ef2e55904fa1d68899dc65a5b65f27763f30254f282b22d8a8f46094`
- Original strict audit: **FAIL**
- Captured frames: 34419
- Source data never modified by this utility.

## Event-level detection evidence

| Phase | Events with matched IDS alert | Structural status |
|---|---:|---|
| A1 | 30/30 | OK |
| A2 | 30/30 | OK |
| A4 | 1/1 | OK |
| A5 | 30/30 | SEMANTIC DEFECT |
| A6 | 30/30 | OK |
| A7 | 30/30 | OK |
| A8 | 30/30 | OK |
| A9 | 30/30 | OK |

## A5: critical distinction

The detector reported a matching `STALE_SEQ` alert for each of 30 recorded A5 events. However, these are **crafted stale-sequence injections** and **not verbatim replays** of a previously captured command/authentication pair.

- Earlier seq=2 motion command: `0028000000000000`
- Earlier seq=2 companion: `CA01FA0900020000`
- A5 injected motion command: `00C8000000000000`
- A5 injected companion: `197B9FE800020000`
- Exact matches to captured earlier pair: **0/30**

## A4: narrower supported finding

The IDS detected one 5-second high-rate CAN command-flooding session. This recording does **not** by itself prove actuator/controller denial of service. 

## False positives

Original physical recording, outside phase windows: 0 alerts / 10414 frames.
A separate software **mock** run reported 1 `BURST` false alert / 14,753 benign frames (0.007%); do not conflate the two.

## Ready-to-use conservative manuscript wording

> The archived physical session contained 30 crafted authentication pairs with valid but stale sequence numbers, and the detector issued a corresponding STALE_SEQ alert for each event. These experiments verify stale-sequence detection; they do not constitute byte-for-byte retransmission of a previously recorded command/authentication pair. Verbatim replay was separately verified in the updated software test harness, without a new physical trial.

> A bounded five-second command-flooding experiment triggered the configured FLOOD detection rule. Because this test did not directly quantify missed legitimate commands or controller availability, we do not claim that service denial was experimentally demonstrated.

## Boundaries

- Physical IDS alerts were reconstructed by offline replay; no online detector latency measurement.
- 30 attacks in one physical recording are not 30 independent sessions.
- The first historical capture must not be represented as a successful literal replay.
- Do not equate no wheel motion during zero-velocity flooding with denial of service.
- This derived analysis is based on the supplied archived file, not independently attested capture provenance.

**Do not convert this qualified report into a PASS of the original strict replay-fidelity audit.**
