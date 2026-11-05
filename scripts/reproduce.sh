#!/usr/bin/env bash
# ==========================================================================
# reproduce.sh — reproduce and self-verify the whole evaluation on a PC,
# with NO robot. Builds the C tools, runs the 8 unit tests, runs the offline
# and mock-live pipelines, checks they agree, runs the sensitivity sweep, and
# regenerates every figure from the measured data.
#
# Run from anywhere:  ./scripts/reproduce.sh
# ==========================================================================
set -e
cd "$(dirname "$0")/.."                      # go to the repository root
export PYTHONPATH=harness                    # let python import the harness modules

echo "== build C tools (src/ -> bin/) =="
make >/dev/null                              # compile everything, run unit tests

echo "== offline experiment =="
python3 harness/run_experiment.py offline 2>/dev/null | sed -n '/experiment/,/wrote/p'
echo "== mock-live experiment (candump -L path, incl. robot feedback) =="
python3 harness/run_experiment.py mock 2>/dev/null | sed -n '/experiment/,/wrote/p'

echo "== cross-check: offline vs mock-live must agree on detection =="
python3 - <<'PY'
import json
o=json.load(open("results/exp_metrics_offline.json"))["attacks"]
m=json.load(open("results/exp_metrics_mock.json"))["attacks"]
bad=[k for k in o if o[k]["detection_rate"]!=m.get(k,{}).get("detection_rate")]
print("  attacks compared:", len(o), "| mismatches:", bad if bad else "none")
assert not bad, "offline and mock-live disagree: "+str(bad)
print("  PASS: both pipelines produce identical detection rates")
PY

echo "== sensitivity sweep + HMAC benchmark + figures =="
python3 harness/sweep.py >/dev/null 2>&1
./bin/bench_hmac 200000 > results/hmac_bench_host.json 2>/dev/null
python3 harness/make_figures.py >/dev/null 2>&1
echo "  figures -> results/charts/"

echo
echo "All reproduced. On the robot, run:  sudo python3 harness/run_experiment.py live --iface can0"
