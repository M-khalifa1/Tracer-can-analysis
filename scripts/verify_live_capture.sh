#!/usr/bin/env bash
# ==========================================================================
# verify_live_capture.sh — reproduce the PHYSICAL-robot results from the real
# capture shipped in data/live_capture/, with NO robot needed. A reviewer runs
# this to confirm the live detection numbers independently.
#
#   ./scripts/verify_live_capture.sh
# ==========================================================================
set -e
cd "$(dirname "$0")/.."                      # repository root
export PYTHONPATH=harness

make >/dev/null                              # ensure bin/ids_runner exists
LOG=data/live_capture/exp_live_session.log   # the real 89 s robot capture
FR=results/live_frames.csv                   # converted frames
AL=results/live_frames_al.csv                # IDS alerts on the capture

echo "== convert the real candump capture =="
python3 harness/candump2csv.py "$LOG" "$FR"

echo "== run the SAME detector over the real capture =="
./bin/ids_runner "$FR" "$AL" seq_window=64 require_auth_mode=1 suppress=0 2>/dev/null

echo "== clock-robust scoring (detection + wheel speed per attack) =="
python3 harness/score_live.py "$FR" "$AL" results/physical_live_metrics.json
