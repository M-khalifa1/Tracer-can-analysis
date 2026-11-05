#!/usr/bin/env python3
"""TRACER manuscript readiness audit, OFFLINE ONLY. Does not transmit CAN frames.

Run after bash scripts/run_safe_verification.sh from repo root. Requires stdlib only.
This utility checks evidence and reports outstanding publication gates honestly.
"""
import hashlib
import json
import os
import pathlib
import platform
import re
import subprocess
import sys
import zipfile
from datetime import datetime, timezone

ROOT=pathlib.Path(__file__).resolve().parent.parent
RESULTS=ROOT/'results'
OUT=RESULTS/'today_final_audit'
PINNED_CAPTURE_SHA='5f7e2ca1ef2e55904fa1d68899dc65a5b65f27763f30254f282b22d8a8f46094'
ORDER=['A1','A2','A4','A5','A6','A7','A8','A9']
EXPECTED={k:(1 if k=='A4' else 30) for k in ORDER}

def load(name):
    with (RESULTS/name).open(encoding='utf-8') as f:return json.load(f)
def sha(path):
    h=hashlib.sha256()
    with path.open('rb') as f:
        while True:
            c=f.read(1024*1024)
            if not c:break
            h.update(c)
    return h.hexdigest()
def getcpu():
    try:
        for ln in pathlib.Path('/proc/cpuinfo').read_text().splitlines():
            if ln.startswith('model name'):
                return ln.split(':',1)[1].strip()
    except OSError:pass
    return platform.processor() or 'unknown'
def extract_log(name):
    return (RESULTS/'fasttrack_logs'/name).read_text(encoding='utf-8',errors='replace')

def main():
    OUT.mkdir(parents=True,exist_ok=True)
    checks={}; notes=[]; blocking=[]
    def check(name, result, reason, is_blocker=True):
        checks[name]={'status':'PASS' if result else 'FAIL','detail':reason}
        if not result and is_blocker:blocking.append(name)
    raw=ROOT/'data/live_capture/exp_live_session.log'
    raw_sha=sha(raw)
    check('archived_capture_integrity',raw_sha==PINNED_CAPTURE_SHA,
          'SHA-256 pinned and unchanged: '+raw_sha)

    make_log=extract_log('make.log')
    neg_log=extract_log('negative_tests.log')
    check('c_regression_8',bool(re.search(r'8 passed, 0 failed',make_log)),
          'C regression log reports 8 passed, 0 failed')
    check('python_negative_tests_6','Ran 6 tests' in neg_log and re.search(r'(?m)^OK\s*$',neg_log) is not None,
          '6 fail-closed/event mutation tests completed')

    dlc_log=extract_log('dlc_parity.log')
    check('mock_offline_can_dlc_fidelity','Ran 1 test' in dlc_log and re.search(r'(?m)^OK\s*$',dlc_log) is not None,
          '0x421 DLC=1 and one-byte payload preserved in mock candump and offline CSV')

    mock=load('strict_mock_capture_audit.json')
    check('mock_strict',mock.get('status')=='PASS' and not mock.get('issues'),
          'strict mock event-level audit passed, no flagged issues')
    for k,n in EXPECTED.items():
        a=mock.get('attacks',{}).get(k,{})
        check('mock_'+k,a.get('expected')==n and a.get('reconstructed')==n and a.get('detected')==n and not a.get('frame_shape_errors'),
              '%s: %s/%s matched in strict mock' %(k,a.get('detected'),n))

    archived=load('archived_strict_audit.json')
    only_a5=archived.get('status')=='FAIL' and archived.get('issues')==['A5: NOT a byte-for-byte replay of earlier seq=2 capture']
    check('archived_qualified_fidelity',only_a5,
          'EXPECTED qualified evidence: original A5 is crafted stale-sequence injection, not literal replay')
    for k,n in EXPECTED.items():
        a=archived.get('attacks',{}).get(k,{})
        good=a.get('expected')==n and a.get('reconstructed')==n and a.get('detected')==n
        if k!='A5':good=good and not a.get('frame_shape_errors')
        check('archived_alert_'+k,good,
              '%s: %s/%s matched archived alert-bearing events (not physical execution proof)' %(k,a.get('detected'),n))
    benign_archived=archived.get('benign',{})
    check('physical_benign_attribution',benign_archived.get('frames_outside_attack_windows')==10414 and benign_archived.get('alerts_outside_attack_windows')==0,
          '0 alert / 10414 frames outside phase-based attack windows')

    offline=load('exp_metrics_offline.json')
    mock_exp=load('exp_metrics_mock.json')
    for name,metrics in [('offline',offline),('mock',mock_exp)]:
        a=metrics.get('attacks',{})
        check(name+'_aggregate_counts',all(a.get(k,{}).get('detected')==n and a.get(k,{}).get('events')==n for k,n in EXPECTED.items()),
              'attack detection numerator/denominator match expected per attack')
    b_mock=mock_exp['benign']; b_strict=mock['benign']
    mismatch=(b_mock['benign_frames']!=b_strict['frames_outside_attack_windows'] or b_mock['false_positives']!=b_strict['alerts_outside_attack_windows'])
    notes.append('BENIGN DENOMINATOR DISAGREEMENT: event-window mock metrics %d alerts/%d frames vs strict phase-window mock %d alerts/%d frames. Do NOT say offline/mock/live use identical FPR scoring; define a common exposure window and re-score before manuscript publication.'% (
        b_mock['false_positives'],b_mock['benign_frames'],b_strict['alerts_outside_attack_windows'],b_strict['frames_outside_attack_windows']))
    notes.append('Original physical: 0 alerts / 10,414 frames outside attack phases; mock event-window: 1 BURST / 14,753 frames; offline event-window: 1 BURST / 108,139 frames. Values have different provenance and window definitions.')
    notes.append('A5 physical: 30/30 STALE_SEQ alerts for crafted valid-MAC stale-sequence events, NOT literal replay; corrected mock A5 is literal replay (30/30).')
    notes.append('A4 physical: ONE 5-second high-rate zero-velocity command flood. FLOOD alert proven, controller availability/DoS not established.')
    notes.append('CAN frames captured on robot and then replayed through IDS; no online IDS latency established.')
    notes.append('n=30 events within one physical campaign, not 30 independent sessions; A4 n=1.')
    notes.append('Prototype fixed authentication key; passive HMAC checks do not prevent controller from consuming unverified frames.')
    notes.append('Submitted PDF and supplied response letter are mutually inconsistent: PDF has prior counter-based replay/eight rules, while the letter describes revised 9-rule/STALE_SEQ experiments.')
    notes.append('Response letter claims 0% false positives in offline/mock/live, but measured offline/mock event-window each have one BURST alert.')
    notes.append('Claims that all host-to-robot commands are protected need qualification: 0x121 lighting command is excluded.')

    sweep=load('validated_threshold_diagnostics.json')
    check('r6_r8_diagnostic_counts',len(sweep.get('r6_valid_companion',[]))==56 and len(sweep.get('r6_missing_companion',[]))==7 and len(sweep.get('r8_legitimate_resumption',[]))==49,
          'R6: 56 valid delayed+7 missing; R8: 49 signed benign configurations')
    r8fp=sum(bool(row['burst_false_alert']) for row in sweep['r8_legitimate_resumption'])
    notes.append('R8 synthetic signed benign resume scenarios with BURST warning: %d/49; do not label all BURST warnings malicious.'%r8fp)
    bench=load('fasttrack_bench_local_only.json')
    check('valid_hmac_benchmark_execution',bench.get('iterations',0)>=10000 and bench.get('sign_us',{}).get('mean',0)>0 and bench.get('verify_us',{}).get('mean',0)>0,
          'benchmark executed with matching authenticated inputs; current host result is illustrative only')

    machine={'hostname_redacted':True,'cpu':getcpu(),'os':platform.platform(),'arch':platform.machine(),
             'python':platform.python_version(),'run_utc':datetime.now(timezone.utc).isoformat(),
             'compiler':subprocess.run(['gcc','--version'],capture_output=True,text=True).stdout.splitlines()[0]}
    notes.append('Benchmark numbers must be taken from the actual Ubuntu deployment host; do not use analysis-host timings.')
    notes.append('Reference/DOI accuracy, comparison table, complete revised manuscript, release availability and editorial deadline require independent final review.')

    manual_gates=[
      'Correct submitted PDF protocol details: 0x111 byte[7] is RESERVED, not stock counter.',
      'Rewrite A5 physical results as crafted valid-MAC stale-sequence injection; separate from software literal-replay demonstration.',
      'Downgrade A4 physical DoS claim to 5-s command-flood detection unless loss-of-service independently measured.',
      'Make R3/R8 explicitly platform-calibrated plausibility warnings; publish only validated sensitivity results with correct rule attribution.',
      'Unify benign-window/FPR methodology across offline/mock/physical; clearly distinguish alert-per-benign-frame proxy from true per-frame classification FPR.',
      'Replace response-letter overclaims: online IDS, 30 independent sessions, all commands authenticated, 0% FPR across all transports.',
      'Measure benchmark on deployment Ubuntu and report hardware/compiler details; do not claim embedded-MCU validation.',
      'Verify citations/DOIs and systematic comparison against actual manuscript; audit all tables/figures for real data.',
      'Finish fully revised manuscript and complete point-by-point response; verify all figure numbers, tables and references.',
      'Verify submission deadline shown in Editorial Manager; do not rely on conflicting relative-date messages.'
    ]
    status='SOFTWARE_VALIDATED__ARCHIVED_QUALIFIED__MANUSCRIPT_NOT_READY' if not blocking else 'SOFTWARE_EVIDENCE_CHECK_FAILED'
    report={'overall_status':status,'final_submission_ready':False,'issues_requiring_attention':notes,
            'manual_submission_gates':manual_gates,'checks':checks,'machine':machine,
            'capture_sha256':raw_sha,'mock_benign_metrics_event_windows':b_mock,
            'mock_benign_metrics_strict_phase_windows':b_strict,
            'physical_benign_metrics_strict_phase_windows':benign_archived,
            'host_benchmark':bench,'benign_metric_definition_mismatch':mismatch,'r8_benign_burst_positive_count':r8fp}
    dest_json=OUT/'verification_today.json'
    dest_json.write_text(json.dumps(report,indent=2,ensure_ascii=False)+'\n',encoding='utf-8')
    lines=['# TRACER 2.0 — Same-day verification (offline/read-only physical evidence)',
           '', '**Gate:** '+status,'', '**Submission-ready:** NO — manuscript and reviewer-response reconciliation still required.',
           '', '## Mechanically verified checks','', '| Check | Status | Detail |','|---|---|---|']
    for k,v in checks.items():lines.append('| %s | %s | %s |'%(k,v['status'],v['detail'].replace('|','/')))
    lines.extend(['','## Defects and scientific boundaries',''])
    lines.extend(f'- {note}' for note in notes)
    lines.extend(['','## Manual submission gates',''])
    lines.extend(f'{i}. {g}' for i,g in enumerate(manual_gates,1))
    lines.extend(['','## Host execution metadata','', '```json',json.dumps(machine,indent=2,ensure_ascii=False),'```',
                  '', 'The raw capture remains unchanged. PASS for software does not certify physical literal replay, proven controller DoS, online IDS latency, or paper readiness.'])
    (OUT/'verification_today.md').write_text('\n'.join(lines)+'\n',encoding='utf-8')
    files=[dest_json,OUT/'verification_today.md',
          RESULTS/'archived_strict_audit.json',RESULTS/'strict_mock_capture_audit.json',
          RESULTS/'exp_metrics_mock.json',RESULTS/'exp_metrics_offline.json',
          RESULTS/'validated_threshold_diagnostics.json',RESULTS/'fasttrack_bench_local_only.json',
          RESULTS/'fasttrack_logs'/'make.log',RESULTS/'fasttrack_logs'/'negative_tests.log',
          RESULTS/'fasttrack_logs'/'archived_physical_audit.log']
    with zipfile.ZipFile(OUT/'TRACER_evidence_for_review.zip','w',zipfile.ZIP_DEFLATED) as z:
        for f in files:z.write(f,arcname=f.relative_to(RESULTS))
    print('\n=== TRACER TODAY FINAL VERIFICATION ===')
    print('SOFTWARE CHECKS:',len(checks)-len(blocking),'/',len(checks),'PASS')
    print('ARCHIVED STRICT:',archived['status'],'A5 only (expected)')
    print('BENIGN SCORING DEFINITIONS:', 'MISMATCH (MUST reconcile)' if mismatch else 'AGREE')
    print('R8 BENIGN BURST WARNINGS:',r8fp,'/',len(sweep['r8_legitimate_resumption']))
    print('SUBMISSION READY: NO (paper/letter not yet reconciled)')
    print('REPORT:',OUT/'verification_today.md')
    print('EVIDENCE ZIP:',OUT/'TRACER_evidence_for_review.zip')
    return 0 if not blocking else 2
if __name__=='__main__':sys.exit(main())
