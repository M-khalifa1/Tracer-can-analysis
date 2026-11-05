#!/usr/bin/env python3
"""Run an offline, mock, or live CAN/IDS evaluation with readable attack progress.

The live progress indicator follows the HOST TRANSMIT SCHEDULE, not the IDS alert
stream. Real IDS verdicts are reported only after the capture is replayed/scored.
No attack traffic, event timestamps, or detection criteria are changed.
"""
from __future__ import annotations

import argparse
from collections import Counter
from datetime import datetime
import json
import os
import signal
import subprocess
import sys
import time
from typing import Any

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _paths
import scenarios
import evaluate as E

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = _paths.RESULTS
os.makedirs(OUT, exist_ok=True)


class Console:
    """Unbuffered terminal messages plus an identical timestamped text log."""

    def __init__(self, path: str):
        self.path = path
        self._file = open(path, "w", encoding="utf-8", buffering=1)

    def say(self, tag: str, message: str) -> None:
        now = datetime.now().astimezone().strftime("%H:%M:%S.%f")[:-3]
        line = f"[{now}] [{tag:<15}] {message}"
        print(line, flush=True)
        self._file.write(line + "\n")

    def close(self) -> None:
        self._file.close()


def _str_field(value: Any) -> str:
    if isinstance(value, (set, frozenset, list, tuple)):
        return ", ".join(sorted(map(str, value)))
    return str(value)


def _rules(kind: str) -> str:
    accepted = E.ATTACKS.get(kind, (set(), kind))[0]
    return _str_field(accepted) if accepted else "not configured"


def show_plan(events: list[dict], console: Console, mode: str) -> None:
    """Present ground-truth windows; do not imply an alert has been observed."""
    ordered = sorted(events, key=lambda e: (int(e["t0"]), int(e["t1"])))
    console.say("SESSION", f"mode={mode.upper()} | attack events={len(ordered)} | "
                f"distinct attack types={len({e['type'] for e in ordered})}")
    console.say("GROUND TRUTH", "Scenario windows are from the original schedule; "
                "detection has not yet been measured.")
    for i, e in enumerate(ordered, start=1):
        kind = str(e["type"])
        start, end = int(e["t0"]), int(e["t1"])
        if end < start:
            raise ValueError(f"Bad event window for {kind}: t1 < t0")
        description = e.get("description") or e.get("name") or e.get("label")
        detail = f" | description={_str_field(description)}" if description else ""
        console.say("PLANNED", f"{i:02}/{len(ordered):02} {kind} | "
                    f"t={start/1e6:.3f}–{end/1e6:.3f} s | "
                    f"duration={(end-start)/1e6:.3f} s | "
                    f"primary IDS rule={E.PRIMARY.get(kind, 'unspecified')} | "
                    f"accepted alerts={_rules(kind)}{detail}")


class LiveAttackProgress:
    """Log live per-event START/PROGRESS/END from can_tx's progress callback.

    Important: callback timestamps refer to the transmit schedule (microseconds).
    They are NOT candump/OS timestamps and cannot be used for live IDS scoring.
    """

    def __init__(self, events: list[dict], console: Console, every_s: float = 1.0):
        self.items = [dict(event=e, number=i + 1, frames=0,
                           started=False, ended=False, last_status=None)
                      for i, e in enumerate(sorted(events,
                                                  key=lambda x: (int(x["t0"]), int(x["t1"]))))]
        self.console = console
        self.every_us = int(max(0.0, every_s) * 1_000_000)
        self.next_event = 0
        self.active: list[dict] = []
        self.host_frames = 0
        self.last_ts: int | None = None

    def _start(self, item: dict, late: bool = False) -> None:
        e = item["event"]
        item["started"] = True
        self.console.say("ATTACK START", f"#{item['number']:02} {e['type']} | "
                         f"scheduled t={int(e['t0'])/1e6:.3f} s | "
                         f"expected IDS={E.PRIMARY.get(e['type'], 'unspecified')}" +
                         (" | reported at next frame checkpoint" if late else ""))

    def _end(self, item: dict, *, checkpoint: bool = False) -> None:
        e = item["event"]
        item["ended"] = True
        self.console.say("ATTACK END", f"#{item['number']:02} {e['type']} | "
                         f"scheduled t={int(e['t1'])/1e6:.3f} s | "
                         f"host frames in window={item['frames']}" +
                         (" | schedule checkpoint / no later callback" if checkpoint else ""))

    def on_frame(self, ts_us: Any, can_id: Any) -> None:
        """Called as can_tx.play_schedule(..., progress=progress.on_frame)."""
        ts = int(ts_us)
        if self.last_ts is not None and ts < self.last_ts:
            raise ValueError("Transmit progress timestamps must be nondecreasing")
        self.last_ts = ts
        self.host_frames += 1

        # Close event windows that ended before this transmitted frame.
        remaining = []
        for item in self.active:
            if ts > int(item["event"]["t1"]):
                self._end(item)
            else:
                remaining.append(item)
        self.active = remaining

        # Open newly reached event windows, including silent event windows.
        while self.next_event < len(self.items):
            item = self.items[self.next_event]
            e = item["event"]
            if ts < int(e["t0"]):
                break
            self.next_event += 1
            late = ts > int(e["t0"])
            self._start(item, late=late)
            if ts > int(e["t1"]):
                self._end(item, checkpoint=True)
            else:
                self.active.append(item)

        # Count only schedule frames inside each exact ground-truth event window.
        for item in self.active:
            item["frames"] += 1
            last_status = item["last_status"]
            if self.every_us and (last_status is None or ts - last_status >= self.every_us):
                e = item["event"]
                item["last_status"] = ts
                self.console.say("ATTACK ACTIVE", f"#{item['number']:02} {e['type']} | "
                                 f"t={ts/1e6:.3f} s | "
                                 f"host frames={item['frames']} | "
                                 f"latest CAN ID={can_id}")

    def finish(self) -> None:
        # A window can end during silence or after the final transmitted frame.
        for item in self.active:
            self._end(item, checkpoint=True)
        self.active.clear()
        for item in self.items[self.next_event:]:
            self._start(item, late=True)
            self._end(item, checkpoint=True)
        self.next_event = len(self.items)
        self.console.say("TX COMPLETE", f"host frames reported by sender={self.host_frames} | "
                         f"ground-truth windows={len(self.items)}")


def score(events, alerts, frames):
    """Exact ground-truth scoring. events: list(dict(type, expect, t0, t1))."""
    res = {"attacks": {}}
    by_type = {}
    for e in events:
        by_type.setdefault(e["type"], []).append(e)
    for kind, evs in sorted(by_type.items()):
        accept = E.ATTACKS.get(kind, ({None}, kind))[0]
        det = 0
        for e in evs:
            if any(ty in accept and e["t0"] - E.GRACE_US <= ts <= e["t1"] + E.GRACE_US
                   for ts, ty in alerts):
                det += 1
        p, lo, hi = E.wilson(det, len(evs))
        res["attacks"][kind] = dict(
            expect=E.PRIMARY.get(kind), events=len(evs), detected=det,
            detection_rate=round(100*p, 1),
            ci95=[round(100*lo, 1), round(100*hi, 1)])

    def in_ev(ts):
        return any(e["t0"] - E.GRACE_US <= ts <= e["t1"] + E.GRACE_US
                   for e in events)

    bf = sum(1 for ts, _ in frames if not in_ev(ts))
    fp = [(ts, ty) for ts, ty in alerts if not in_ev(ts)]
    counts = Counter(ty for _, ty in fp)
    res["benign"] = dict(
        benign_frames=bf, false_positives=len(fp),
        fpr_percent=round(100 * len(fp) / max(bf, 1), 3),
        by_rule=dict(sorted(counts.items(), key=lambda x: str(x[0]))))
    return res


def load_frames(csv):
    fr = []
    with open(csv, encoding="utf-8") as file:
        for ln in file:
            if ln.startswith("ts_us"):
                continue
            p = ln.split(",")
            if len(p) >= 4:
                try:
                    fr.append((int(p[0]), p[1]))
                except ValueError:
                    pass
    return fr


def show_event_verdicts(events, alerts, console):
    """Only valid when events and IDS alerts share the offline/mock clock."""
    for i, e in enumerate(sorted(events, key=lambda ev: (ev["t0"], ev["t1"])), 1):
        accepted = E.ATTACKS.get(e["type"], ({None}, e["type"]))[0]
        matches = sorted((ts, typ) for ts, typ in alerts
                         if typ in accepted and
                         e["t0"] - E.GRACE_US <= ts <= e["t1"] + E.GRACE_US)
        if matches:
            ts, typ = matches[0]
            console.say("IDS DETECTED", f"#{i:02} {e['type']} | "
                        f"first accepted alert={typ} | alert t={ts/1e6:.3f} s | "
                        f"matching alerts={len(matches)}")
        else:
            console.say("IDS NOT SEEN", f"#{i:02} {e['type']} | "
                        "no accepted alert in ground-truth window ± grace")


def run_offline(n, console):
    console.say("BUILD", f"Building OFFLINE scenario, n={n}")
    tr = scenarios.build_session(live=False, n=n)
    show_plan(tr.events, console, "offline")
    fcsv = os.path.join(OUT, "exp_offline_frames.csv")
    tr.write_csv(fcsv)
    console.say("REPLAY START", f"Offline IDS evaluation: {fcsv}")
    alerts = list(E.run_detector(fcsv, {"seq_window": 64, "require_auth_mode": 1, "suppress": 0}))
    console.say("REPLAY END", f"Detector returned {len(alerts)} alerts")
    frames = load_frames(fcsv)
    show_event_verdicts(tr.events, alerts, console)
    return score(tr.events, alerts, frames), tr


def _stop_capture(rec, console):
    if rec.poll() is None:
        rec.send_signal(signal.SIGINT)
        try:
            rec.wait(timeout=8)
        except subprocess.TimeoutExpired:
            console.say("CAPTURE WARN", "candump did not stop after SIGINT; terminating")
            rec.terminate()
            try:
                rec.wait(timeout=3)
            except subprocess.TimeoutExpired:
                rec.kill()
                rec.wait()


def run_live(iface, n, console, duration_pad=5.0, status_every=1.0):
    import can_tx
    console.say("SAFETY", "Confirm wheels on blocks, RC e-stop available, "
                "and authorized isolated test environment")
    console.say("BUILD", f"Building LIVE scenario, n={n}")
    tr = scenarios.build_session(live=True, n=n)
    show_plan(tr.events, console, "live")
    frames = tr._materialise()  # original host-side schedule
    progress = LiveAttackProgress(tr.events, console, every_s=status_every)
    # Unique non-overwriting capture path: never lose raw bus evidence.
    from datetime import datetime, timezone
    session_id = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
    log = os.path.join(OUT, f"exp_live_session_{session_id}.log")
    console.say("CAPTURE START", f"Starting candump on {iface}; raw bus log={log}")
    with open(log, "x", encoding="utf-8") as capture_file:
        rec = subprocess.Popen(["candump", "-L", iface], stdout=capture_file)
        try:
            time.sleep(1.0)
            if rec.poll() is not None:
                raise RuntimeError("candump exited before transmission; check interface")
            console.say("TX START", f"Transmitting {len(frames)} host frames on {iface}; "
                        "live messages reflect scheduled transmission, NOT IDS decisions")
            can_tx.play_schedule(iface, frames, progress=progress.on_frame)
            progress.finish()
            console.say("POST-TX", f"Waiting {duration_pad:g} seconds for bus feedback/timeouts")
            time.sleep(duration_pad)
        finally:
            _stop_capture(rec, console)
    console.say("CAPTURE END", "candump process stopped; converting captured CAN data")

    fcsv = os.path.join(OUT, f"exp_live_frames_{session_id}.csv")
    subprocess.run([sys.executable, os.path.join(HERE, "candump2csv.py"), log, fcsv], check=True)
    acsv = fcsv.replace(".csv", "_al.csv")
    console.say("IDS START", "Replaying actual CAN capture through the shared IDS")
    E.run_detector(fcsv, {"seq_window": 64, "require_auth_mode": 1, "suppress": 0})
    console.say("IDS END", "Using capture-phase scorer (not scheduled absolute timestamps)")

    # The legacy phase scorer by itself can mask missing trials. Fail CLOSED
    # on the independent per-event audit before emitting an accepted live metric.
    import strict_capture_audit as STRICT
    audit_path = os.path.join(OUT, f'strict_live_capture_{session_id}.json')
    evidence = STRICT.audit(fcsv, acsv, n)
    with open(audit_path, 'w', encoding='utf-8') as f:
        json.dump(evidence, f, indent=2)
    console.say('STRICT AUDIT', f"{evidence['status']} | details={audit_path}")
    if evidence['status'] != 'PASS':
        raise RuntimeError('Live capture strict event/fidelity audit failed; '
                           'no validated live score will be published. '
                           + '; '.join(evidence['issues'][:3]))
    # Keep telemetry and phase-table fields from the legacy scorer only after
    # replacing its alert-capped event results with strict one-to-one evidence.
    import score_live
    result = score_live.score_capture(fcsv, acsv)
    for kind, row in evidence['attacks'].items():
        a = result['attacks'][kind]
        a['events'] = row['expected']
        a['detected'] = row['detected']
        prop, lo, hi = E.wilson(row['detected'], row['expected'])
        a['detection_rate'] = round(100 * prop, 1)
        a['ci95'] = [round(100 * lo, 1), round(100 * hi, 1)]
        a['strict_event_reconstructed'] = row['reconstructed']
    result['strict_audit_status'] = 'PASS'
    result['strict_audit_path'] = audit_path
    result['session_id'] = session_id
    result['original_capture_path'] = log
    return result, tr


def run_mock(n, console):
    """Same mock capture + replay + original exact-timestamp scorer."""
    import mock_bus
    console.say("BUILD", f"Building MOCK-LIVE scenario, n={n}")
    tr = scenarios.build_session(live=True, n=n)
    show_plan(tr.events, console, "mock")
    frames = tr._materialise()
    log = os.path.join(OUT, "exp_mock_session.log")
    console.say("MOCK START", f"Rendering {len(frames)} host frames plus simulated feedback")
    mock_bus.capture_log(frames, log)
    console.say("MOCK END", f"Software-bus capture written: {log}")
    fcsv = os.path.join(OUT, "exp_mock_frames.csv")
    subprocess.run([sys.executable, os.path.join(HERE, "candump2csv.py"), log, fcsv], check=True)
    console.say("IDS START", "Replaying mock capture through IDS")
    alerts = list(E.run_detector(fcsv, {"seq_window": 64, "require_auth_mode": 1, "suppress": 0}))
    console.say("IDS END", f"Detector returned {len(alerts)} alerts")
    import strict_capture_audit as STRICT
    acsv = fcsv.replace('.csv', '_al.csv')
    audit_path = os.path.join(OUT, 'strict_mock_capture_audit.json')
    evidence = STRICT.audit(fcsv, acsv, n)
    with open(audit_path, 'w', encoding='utf-8') as f:
        json.dump(evidence, f, indent=2)
    console.say('STRICT AUDIT', f"{evidence['status']} | details={audit_path}")
    if evidence['status'] != 'PASS':
        raise RuntimeError('Mock capture failed event-level/fidelity audit: '
                           + '; '.join(evidence['issues'][:3]))
    cap = load_frames(fcsv)
    show_event_verdicts(tr.events, alerts, console)
    result = score(tr.events, alerts, cap)
    for kind, row in evidence['attacks'].items():
        a = result['attacks'][kind]
        a['events'] = row['expected']
        a['detected'] = row['detected']
        prop, lo, hi = E.wilson(row['detected'], row['expected'])
        a['detection_rate'] = round(100 * prop, 1)
        a['ci95'] = [round(100 * lo, 1), round(100 * hi, 1)]
    result['strict_audit_status'] = 'PASS'
    return result, tr


def print_summary(mode, res, console):
    console.say("SUMMARY", f"{mode.upper()} per-attack detection (95% Wilson CI)")
    for k in sorted(res["attacks"]):
        a = res["attacks"][k]
        console.say("IDS RESULT", f"{k} | detected={a['detected']}/{a['events']} | "
                    f"rate={a['detection_rate']:.1f}% | "
                    f"95% CI=[{a['ci95'][0]}, {a['ci95'][1]}]% | "
                    f"expected rule={a['expect']}")
    b = res["benign"]
    console.say("BENIGN", f"false positives={b['false_positives']} | "
                f"benign frames={b['benign_frames']} | "
                f"FPR={b['fpr_percent']}% | by rule={b['by_rule']}")


def main():
    ap = argparse.ArgumentParser(description="CAN security evaluation with attack timeline output")
    ap.add_argument("mode", choices=["offline", "live", "mock"])
    ap.add_argument("--iface", default="can0")
    ap.add_argument("--n", type=int, default=scenarios.N)
    ap.add_argument("--status-every", type=float, default=1.0,
                    help="Live per-attack progress interval in seconds; 0 disables intermediate status")
    ap.add_argument('--render-figures', action='store_true',
                    help='Explicitly regenerate figures; inspect sensitivity sources first')
    ap.add_argument('--acknowledge-lab-risk', action='store_true',
                    help='Required for live: confirms isolated lab, immobilized UGV and working e-stop')
    args = ap.parse_args()
    if args.n < 1:
        ap.error("--n must be >= 1")
    if args.status_every < 0:
        ap.error("--status-every must be >= 0")
    if args.mode == 'live' and not args.acknowledge_lab_risk:
        ap.error('live mode requires --acknowledge-lab-risk after completing physical safety checks')

    log_path = os.path.join(OUT, f"exp_console_{args.mode}.log")
    console = Console(log_path)
    try:
        console.say("EXPERIMENT", f"Started | mode={args.mode.upper()} | terminal log={log_path}")
        if args.mode == "offline":
            res, _ = run_offline(args.n, console)
        elif args.mode == "mock":
            res, _ = run_mock(args.n, console)
        else:
            res, _ = run_live(args.iface, args.n, console, status_every=args.status_every)

        metric_name = (f"exp_metrics_live_{res['session_id']}.json"
                       if args.mode == 'live' else f"exp_metrics_{args.mode}.json")
        outp = os.path.join(OUT, metric_name)
        with open(outp, "w", encoding="utf-8") as file:
            json.dump(res, file, indent=2)
        print_summary(args.mode, res, console)
        console.say("SAVED", f"metrics={outp} | terminal log={log_path}")
        if args.render_figures:
            console.say("FIGURES", "Regenerating figures on explicit request")
            fig = subprocess.run([sys.executable, os.path.join(HERE, "make_figures.py")],
                                 capture_output=True, text=True)
            if fig.returncode:
                raise RuntimeError('Figure regeneration failed: ' + fig.stderr[-300:])
        else:
            console.say("FIGURES SKIP", "Not auto-regenerating plots from potentially stale sweeps")
        console.say("COMPLETE", f"Experiment finished successfully ({args.mode.upper()})")
    except KeyboardInterrupt:
        console.say("INTERRUPTED", "Experiment stopped by operator")
        raise SystemExit(130)
    except Exception as exc:
        console.say("ERROR", f"{type(exc).__name__}: {exc}")
        raise
    finally:
        console.close()


if __name__ == "__main__":
    main()
