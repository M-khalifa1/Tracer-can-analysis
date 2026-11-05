#!/usr/bin/env bash
# Safe offline verification, no physical CAN traffic or SocketCAN access.
set -euo pipefail
cd "$(dirname "$0")/.."
echo "[1/2] Running software/mock/archived-capture checks (no physical robot commands)"
bash scripts/run_safe_verification.sh
echo "[2/2] Writing truthful same-day submission-readiness report and evidence ZIP"
python3 harness/test_dlc_parity.py > results/fasttrack_logs/dlc_parity.log 2>&1
python3 scripts/verify_today.py
