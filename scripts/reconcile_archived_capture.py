#!/usr/bin/env python3
"""Read-only reconciliation of the ORIGINAL archived TRACER physical CAN capture.

The strict audit must remain FAIL when A5 is not an exact copied pair. This tool
replays the original raw capture with the current detector, performs the strict
per-event audit, and emits separate observations for alert evidence and attack
semantics. Its successful exit code means that the EXPECTED HISTORICAL
DISCREPANCY was confirmed, not that every attack claim passed validation.

Install alongside a TRACER project, e.g. scripts/reconcile_archived_capture.py:
    python3 scripts/reconcile_archived_capture.py
"""
from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import subprocess
import sys
import tempfile
from datetime import datetime, timezone

KNOWN_ORIGINAL_SHA256 = '5f7e2ca1ef2e55904fa1d68899dc65a5b65f27763f30254f282b22d8a8f46094'
EXPECTED_ISSUE = 'A5: NOT a byte-for-byte replay of earlier seq=2 capture'
ORDER = ('A1', 'A2', 'A4', 'A5', 'A6', 'A7', 'A8', 'A9')


def _hexpair(pair):
    x, y = pair
    return {'command_can_id': f'0x{x[1]:03X}', 'command_payload_hex': x[2].hex().upper(),
            'companion_can_id': f'0x{y[1]:03X}', 'companion_payload_hex': y[2].hex().upper()}


def _sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def reconcile(repo: pathlib.Path):
    sys.path.insert(0, str(repo / 'harness'))
    import strict_capture_audit as audit  # noqa: E402

    capture = repo / 'data/live_capture/exp_live_session.log'
    runner = repo / 'bin/ids_runner'
    converter = repo / 'harness/candump2csv.py'
    for path in (capture, runner, converter):
        if not path.is_file():
            raise RuntimeError(f'Missing required project file: {path}')
    digest = _sha(capture)
    if digest != KNOWN_ORIGINAL_SHA256:
        raise RuntimeError('Capture SHA-256 differs from audited original: ' + digest)

    # The detector runs on TEMPORARY derived CSV files, never changes the raw log.
    with tempfile.TemporaryDirectory(prefix='tracer_readonly_archive_') as tmp:
        frames = pathlib.Path(tmp) / 'frames.csv'
        alerts = pathlib.Path(tmp) / 'alerts.csv'
        subprocess.run([sys.executable, str(converter), str(capture), str(frames)],
                       check=True, capture_output=True, text=True)
        subprocess.run([str(runner), str(frames), str(alerts), 'seq_window=64',
                        'require_auth_mode=1', 'suppress=0'], check=True,
                       capture_output=True, text=True)
        strict = audit.audit(str(frames), str(alerts), 30)
        rows = audit.load_frames(str(frames))

    phases = audit.phase_groups([r for r in rows if r[1] in audit.HOST_IDS])
    if len(phases) != 10:
        raise RuntimeError(f'Expected exactly 10 phases; saw {len(phases)}')
    baseline = audit.split_pairs(phases[0], [], 'baseline')
    earlier = [(x, y) for x, y in baseline if y[1] == 0x112 and len(y[2]) >= 6
               and int.from_bytes(y[2][4:6], 'big') == 2]
    replay_pairs = audit.split_pairs(phases[5], [], 'A5')[-30:]
    if len(earlier) != 1 or len(replay_pairs) != 30:
        raise RuntimeError('Cannot establish unique source seq=2 / 30 A5 attempts')
    ref = earlier[0]
    copied = sum(x[1:] == ref[0][1:] and y[1:] == ref[1][1:]
                 for x, y in replay_pairs)
    expected_structure = (
        strict.get('status') == 'FAIL'
        and strict.get('issues') == [EXPECTED_ISSUE]
        and set(strict.get('attacks', {})) == set(ORDER)
        and all(strict['attacks'][k]['detected'] == strict['attacks'][k]['expected']
                and strict['attacks'][k]['reconstructed'] == strict['attacks'][k]['expected']
                for k in ORDER)
        and copied == 0
    )
    report = {
        'status': 'QUALIFIED_ARCHIVED_EVIDENCE' if expected_structure else 'UNEXPECTED_AUDIT_FINDINGS',
        'interpretation': 'Observed IDS alerts, not proof of the stronger attack semantics',
        'capture_sha256': digest,
        'strict_audit_status': strict['status'],
        'strict_issues': strict['issues'],
        'original_frames': strict['total_captured_frames'],
        'phase_count': strict['phase_count'],
        'attacks': {k: {'reconstructed': strict['attacks'][k]['reconstructed'],
                        'matched_alerts_one_to_one': strict['attacks'][k]['detected'],
                        'expected': strict['attacks'][k]['expected'],
                        'structural_findings': strict['attacks'][k]['frame_shape_errors']}
                    for k in ORDER},
        'A5_semantics': {
            'actual_archived_experiment': 'crafted valid-MAC stale-sequence injection',
            'old_claim_literal_replay_supported': False,
            'source_pair': _hexpair(ref),
            'injection_pair_example': _hexpair(replay_pairs[0]),
            'verbatim_replays_of_source_pair': copied,
            'attempts_observed': len(replay_pairs),
            'ids_alert_type': 'STALE_SEQ',
            'note': 'The software-corrected A5 generator has passed mock validation, not a new physical run.'
        },
        'A4_semantics': {
            'observed': 'One 5-second ~1kHz frame-flooding session; FLOOD alerts',
            'not_established': 'Physical controller denial of service or legitimate command starvation'
        },
        'benign': strict['benign'],
        'limitations': [
            'Physical IDS alerts were reconstructed by offline replay; no online detector latency measurement.',
            '30 attacks in one physical recording are not 30 independent sessions.',
            'The first historical capture must not be represented as a successful literal replay.',
            'Do not equate no wheel motion during zero-velocity flooding with denial of service.',
            'This derived analysis is based on the supplied archived file, not independently attested capture provenance.'
        ],
    }
    return report, expected_structure


def write_report(repo: pathlib.Path, report: dict):
    out = repo / 'results'
    out.mkdir(parents=True, exist_ok=True)
    jpath = out / 'archived_claims_reconciled.json'
    mpath = out / 'archived_claims_reconciled.md'
    jpath.write_text(json.dumps(report, indent=2, ensure_ascii=False) + '\n', encoding='utf-8')
    lines = ['# Archived TRACER physical capture — independent claim reconciliation', '',
             '**NOT a full strict PASS.** ' + report['status'] + '.', '',
             f"- Raw capture SHA-256: `{report['capture_sha256']}`",
             f"- Original strict audit: **{report['strict_audit_status']}**", 
             f"- Captured frames: {report['original_frames']}",
             '- Source data never modified by this utility.', '',
             '## Event-level detection evidence', '',
             '| Phase | Events with matched IDS alert | Structural status |',
             '|---|---:|---|']
    for kind, row in report['attacks'].items():
        ok = 'OK' if not row['structural_findings'] else 'SEMANTIC DEFECT'
        lines.append(f"| {kind} | {row['matched_alerts_one_to_one']}/{row['expected']} | {ok} |")
    lines += ['', '## A5: critical distinction', '',
              'The detector reported a matching `STALE_SEQ` alert for each of 30 recorded A5 events. '
              'However, these are **crafted stale-sequence injections** and **not verbatim replays** of a previously captured command/authentication pair.', '',
              f"- Earlier seq=2 motion command: `{report['A5_semantics']['source_pair']['command_payload_hex']}`",
              f"- Earlier seq=2 companion: `{report['A5_semantics']['source_pair']['companion_payload_hex']}`",
              f"- A5 injected motion command: `{report['A5_semantics']['injection_pair_example']['command_payload_hex']}`",
              f"- A5 injected companion: `{report['A5_semantics']['injection_pair_example']['companion_payload_hex']}`",
              f"- Exact matches to captured earlier pair: **{report['A5_semantics']['verbatim_replays_of_source_pair']}/30**", '',
              '## A4: narrower supported finding', '',
              'The IDS detected one 5-second high-rate CAN command-flooding session. '
              'This recording does **not** by itself prove actuator/controller denial of service. ', '',
              '## False positives', '',
              f"Original physical recording, outside phase windows: {report['benign']['alerts_outside_attack_windows']} alerts / {report['benign']['frames_outside_attack_windows']} frames.",
              'A separate software **mock** run reported 1 `BURST` false alert / 14,753 benign frames (0.007%); do not conflate the two.', '',
              '## Ready-to-use conservative manuscript wording', '',
              '> The archived physical session contained 30 crafted authentication pairs with valid but stale sequence numbers, and the detector issued a corresponding STALE_SEQ alert for each event. These experiments verify stale-sequence detection; they do not constitute byte-for-byte retransmission of a previously recorded command/authentication pair. Verbatim replay was separately verified in the updated software test harness, without a new physical trial.', '',
              '> A bounded five-second command-flooding experiment triggered the configured FLOOD detection rule. Because this test did not directly quantify missed legitimate commands or controller availability, we do not claim that service denial was experimentally demonstrated.', '',
              '## Boundaries', '',
              *[f'- {v}' for v in report['limitations']], '',
              '**Do not convert this qualified report into a PASS of the original strict replay-fidelity audit.**', '']
    mpath.write_text('\n'.join(lines), encoding='utf-8')
    return jpath, mpath


def main():
    pa = argparse.ArgumentParser(description=__doc__)
    pa.add_argument('--repo', type=pathlib.Path, default=pathlib.Path(__file__).resolve().parent.parent,
                    help='TRACER project directory (defaults to parent of scripts/)')
    args = pa.parse_args()
    repo = args.repo.resolve()
    try:
        report, ok = reconcile(repo)
        jpath, mpath = write_report(repo, report)
    except (RuntimeError, OSError, subprocess.CalledProcessError, ValueError) as e:
        print(f'RECONCILIATION ERROR: {e}', file=sys.stderr)
        return 2
    print('ARCHIVED RAW CAPTURE: UNCHANGED and SHA-256 VERIFIED')
    print('STRICT AUDIT: ' + report['strict_audit_status'] + ' (expected A5 semantics issue)')
    for k,v in report['attacks'].items():
        print(f"  {k}: {v['matched_alerts_one_to_one']}/{v['expected']} alert-matched events" +
              ('; A5 original is NOT literal replay' if k == 'A5' else ''))
    print('ARCHIVED RECONCILIATION: ' + report['status'])
    print('REPORT: ' + str(mpath))
    print('JSON: ' + str(jpath))
    return 0 if ok else 1


if __name__ == '__main__':
    raise SystemExit(main())
