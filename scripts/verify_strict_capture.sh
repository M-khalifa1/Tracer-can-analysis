#!/usr/bin/env bash
# Validate archived physical evidence. Expected to FAIL on A5 fidelity until a
# fresh capture of literal replay exists. NEVER overwrite original raw capture.
set -euo pipefail
cd "$(dirname "$0")/.."
make -s bin/ids_runner
python3 harness/candump2csv.py data/live_capture/exp_live_session.log results/archived_strict_frames.csv
./bin/ids_runner results/archived_strict_frames.csv results/archived_strict_frames_al.csv seq_window=64 require_auth_mode=1 suppress=0 2>results/archived_strict_detector.log
python3 harness/strict_capture_audit.py --frames results/archived_strict_frames.csv --alerts results/archived_strict_frames_al.csv --n 30 --out results/archived_strict_audit.json
