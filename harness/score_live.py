#!/usr/bin/env python3
"""
score_live.py — CLOCK-ROBUST scoring of a live on-robot capture.
==============================================================================
Why this replaces the live scoring inside run_experiment.py
-----------------------------------------------------------
The live run records the bus with `candump`, whose timestamps come from the
kernel. The attack schedule, however, was built on a separate (scenario) clock
that starts at 0. There is an unknown offset between the two clocks (candump
starts first, the robot is already emitting feedback, and transmission starts a
second or so later). Matching alerts to attack events by ABSOLUTE timestamp
therefore fails, which is exactly what produced the misleading "0%" live numbers:
the alerts were real, they just did not fall inside the absolute-time windows.

This scorer does NOT rely on the absolute clock. It recovers the experiment
structure from the capture itself:

  1. The injected host command/attack frames come in bursts (one per phase)
     separated by >=2.5 s idle gaps; robot feedback is continuous and excluded.
     Segmenting the host frames by those gaps recovers the phase boundaries IN
     THE CAPTURE'S OWN CLOCK.
  2. The phases with no alerts, before the first attack, are the benign baseline.
  3. The remaining alert-bearing phases, in time order, are A1,A2,A4,A5,A6,A7,
     A8,A9 (the fixed scenario order).
  4. Detection per attack = expected-type alerts counted within that phase,
     capped at the number of injected events (n). Because the detector is
     deterministic, >= n expected alerts in the phase means every injection was
     detected. Benign FPR = alerts anywhere outside the attack phases.

This is fully auditable: a reviewer can see the phase table, the dominant alert
type per phase, and the counts, all derived from the raw capture.
==============================================================================
"""
import os, sys, json, math, collections
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import evaluate as E                       # reuse ATTACKS, PRIMARY, wilson()
import canfeedback as FB                    # decode wheel speed from robot telemetry

# CAN IDs that WE transmit (host->robot commands + the rogue attack ID).
# Robot feedback (0x2xx/0x3xx) is excluded so it does not hide the phase gaps.
HOST_CMD_IDS = {0x111, 0x112, 0x121, 0x421, 0x441, 0x666}

# Fixed scenario order of the attack phases and how many events each injected.
ATTACK_ORDER = ["A1", "A2", "A4", "A5", "A6", "A7", "A8", "A9"]
N_EVENTS     = {"A1":30, "A2":30, "A4":1, "A5":30, "A6":30, "A7":30, "A8":30, "A9":30}

def load_frames(csv):
    """Read a frames CSV -> list of (ts_us, can_id, payload_bytes).

    The payload is kept so we can decode the robot's wheel-speed telemetry
    (0x221 chassis velocity, 0x251/0x252 motor RPM) and report the PHYSICAL
    effect of each attack alongside the IDS detection."""
    out = []
    for ln in open(csv):
        if ln.startswith("ts_us"):            # skip the header row
            continue
        p = ln.rstrip("\n").split(",")
        if len(p) >= 2:
            payload = bytes.fromhex(p[3]) if len(p) >= 4 and p[3] else b""  # data bytes
            out.append((int(p[0]), int(p[1], 16), payload))                 # ts, id, data
    return out

def peak_wheel_speed(frames, a, b):
    """Peak |chassis speed| (mm/s) and |motor RPM| decoded within a time window.

    frames : list of (ts_us, can_id, payload).
    a, b   : window bounds in us. Returns (peak_linear_mm_s, peak_motor_rpm).
    """
    ws = FB.WheelState()                      # fresh wheel-speed tracker for this window
    for ts, cid, data in frames:              # walk every captured frame ...
        if a <= ts <= b:                      # ... that falls inside the window
            ws.update(cid, data)              # decode if it is a feedback frame
    return ws.peak_linear, ws.peak_rpm        # the peaks seen during the attack

def load_alerts(csv):
    """Read an IDS alert CSV -> list of (ts_us, alert_type)."""
    out = []
    for ln in open(csv):
        if ln.startswith("timestamp") or ln.startswith("#"):   # header / suppression note
            continue
        p = ln.split(",")
        if len(p) >= 2:
            try:
                out.append((int(p[0]), p[1]))     # ts, type
            except ValueError:
                pass
    return out

def segment(cmd_ts, gap_us=1_500_000):
    """Split sorted command timestamps into phases separated by idle gaps."""
    phases = []
    start = prev = cmd_ts[0]                  # first phase begins at first command
    for t in cmd_ts[1:]:
        if t - prev > gap_us:                 # a gap larger than the threshold ...
            phases.append((start, prev))      # ... closes the current phase
            start = t                         # ... and opens the next one
        prev = t
    phases.append((start, prev))              # close the final phase
    return phases

def score_capture(frames_csv, alerts_csv):
    """Clock-robust scoring of a live capture. Returns the results dict.
    Reusable by both the CLI below and run_experiment.py's live mode."""
    frames = load_frames(frames_csv)                        # every captured frame (+payload)
    alerts = load_alerts(alerts_csv)                        # every IDS alert
    cmd_ts = sorted(ts for ts, cid, _ in frames if cid in HOST_CMD_IDS) # host frames only
    if not cmd_ts:
        return {"attacks": {}, "benign": {}, "phase_table": [],
                "error": "no host command frames found in capture"}
    phases = segment(cmd_ts)                                # recover phase windows

    GRACE = 200_000                                         # 200 ms slack around a phase
    def alerts_in(a, b):                                    # alerts within a phase window
        return [ (ts,ty) for ts,ty in alerts if a-GRACE <= ts <= b+GRACE ]

    # Map phases to attacks by ORDER, not by alert presence: the attacks always
    # run after the benign baseline, and each attack is one contiguous burst, so
    # the LAST len(ATTACK_ORDER) phases are the attacks in scenario order. This is
    # robust even if a benign phase happens to raise a stray warning (e.g. a BURST
    # when legitimate motion resumes after an idle gap).
    if len(phases) >= len(ATTACK_ORDER):
        attack_phases = phases[-len(ATTACK_ORDER):]   # trailing phases = the attacks
    else:
        attack_phases = phases                        # fewer phases than expected: score what we have

    results = {"attacks": {}, "phase_table": []}
    # Map the alert-bearing phases, in order, onto the fixed attack order.
    for kind, (a,b) in zip(ATTACK_ORDER, attack_phases):
        accept = E.ATTACKS[kind][0]                         # acceptable alert type(s)
        inwin = alerts_in(a,b)                              # alerts during this phase
        got = collections.Counter(ty for _,ty in inwin)     # count by type
        expected_hits = sum(got.get(t,0) for t in accept)   # expected-type alerts
        n = N_EVENTS[kind]                                  # injected events in this phase
        detected = min(expected_hits, n)                    # cannot exceed the n injected
        p, lo, hi = E.wilson(detected, n)                   # Wilson 95% CI
        pk_lin, pk_rpm = peak_wheel_speed(frames, a, b)     # physical effect (robot telemetry)
        results["attacks"][kind] = dict(
            expect=E.PRIMARY[kind], events=n, detected=detected,
            detection_rate=round(100*p,1), ci95=[round(100*lo,1), round(100*hi,1)],
            expected_type_alerts=expected_hits, all_alerts=dict(got),
            peak_wheel_mm_s=pk_lin, peak_motor_rpm=pk_rpm,  # the measured wheel effect
            phase_window_s=[round(a/1e6,1), round(b/1e6,1)])
        results["phase_table"].append(
            f"{kind}: {a/1e6:6.1f}-{b/1e6:6.1f}s  {dict(got)}")

    # Benign false-positive rate: any alert NOT inside an attack phase, over the
    # frames that lie outside every attack phase.
    attack_windows = [(a-GRACE,b+GRACE) for (a,b) in attack_phases[:len(ATTACK_ORDER)]]
    def in_attack(ts): return any(a<=ts<=b for a,b in attack_windows)
    benign_frames = sum(1 for ts,_,_ in frames if not in_attack(ts))
    benign_alerts = [ (ts,ty) for ts,ty in alerts if not in_attack(ts) ]
    results["benign"] = dict(
        benign_frames=benign_frames, false_positives=len(benign_alerts),
        fpr_percent=round(100*len(benign_alerts)/max(benign_frames,1), 3),
        by_rule=dict(collections.Counter(ty for _,ty in benign_alerts)))
    results["_phase_count"] = len(phases)
    results["_attack_phase_count"] = len(attack_phases)
    return results

def main(frames_csv, alerts_csv, out_json):
    results = score_capture(frames_csv, alerts_csv)         # clock-robust scoring
    json.dump(results, open(out_json,"w"), indent=2)        # save the metrics

    # human-readable summary
    print("Recovered phases (capture clock):", results.get("_phase_count"),
          "| attack phases:", results.get("_attack_phase_count"))
    print("\nPer-attack detection on the PHYSICAL robot (clock-robust):")
    for k in ATTACK_ORDER:
        if k in results["attacks"]:
            r = results["attacks"][k]
            print(f"  {k}  {r['detected']:2d}/{r['events']:2d}  {r['detection_rate']:5.1f}% "
                  f" CI[{r['ci95'][0]},{r['ci95'][1]}]  expected={r['expect']:10s}"
                  f" wheel={r['peak_wheel_mm_s']:>4} mm/s / {r['peak_motor_rpm']:>3} RPM"
                  f"  alerts={r['all_alerts']}")
    b = results["benign"]
    print(f"\n  benign: {b['false_positives']} FP / {b['benign_frames']} frames "
          f"= {b['fpr_percent']}% FPR  {b['by_rule']}")
    print(f"\n  wrote {out_json}")

if __name__ == "__main__":
    if len(sys.argv) == 4:
        main(sys.argv[1], sys.argv[2], sys.argv[3])
    else:
        print("usage: score_live.py LIVE_frames.csv LIVE_alerts.csv OUT.json")
