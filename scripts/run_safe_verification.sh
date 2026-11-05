#!/usr/bin/env bash
# OFFLINE / MOCK ONLY. Does NOT open SocketCAN or transmit physical frames.
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p results/fasttrack_logs
make -j2 >results/fasttrack_logs/make.log 2>&1
PYTHONPATH=harness python3 harness/test_fasttrack.py >results/fasttrack_logs/negative_tests.log 2>&1
python3 -u harness/run_experiment.py offline >results/fasttrack_logs/offline.log 2>&1
python3 -u harness/run_experiment.py mock >results/fasttrack_logs/mock.log 2>&1
python3 harness/sweep_validated.py >results/fasttrack_logs/sweep_validated.log 2>&1
./bin/bench_hmac 10000 >results/fasttrack_bench_local_only.json
# Old physical capture MUST be preserved as evidence even if scientific semantics fail.
set +e
bash scripts/verify_strict_capture.sh >results/fasttrack_logs/archived_physical_audit.log 2>&1
archive_rc=$?
set -e
if [[ "$archive_rc" -eq 1 ]] && grep -q 'A5: NOT a byte-for-byte replay' results/fasttrack_logs/archived_physical_audit.log; then
    echo 'ARCHIVED_PHYSICAL: A5 replay fidelity INVALID (expected; unchanged original data)'
elif [[ "$archive_rc" -eq 0 ]]; then
    echo 'ARCHIVED_PHYSICAL: strict audit PASS (review provenance)' 
else
    echo "ARCHIVED_PHYSICAL: unexpected audit outcome exit=$archive_rc" >&2
    exit 3
fi
python3 - <<'PY'
import json, pathlib
r=pathlib.Path('results')
a=json.loads((r/'strict_mock_capture_audit.json').read_text())
assert a['status']=='PASS',a['issues']
for k,v in a['attacks'].items():
    assert v['detected']==v['expected'],k
print('SOFTWARE MOCK STRICT AUDIT: PASS')
print('OFFLINE / MOCK REGRESSIONS / R6-R8 DIAGNOSTICS: COMPLETE')
print('NO PHYSICAL TRACER SESSION WAS EXECUTED.')
PY
