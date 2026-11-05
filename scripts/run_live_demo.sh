#!/usr/bin/env bash
# ==========================================================================
# run_live_demo.sh — one command to record the on-robot evidence.
#   1) build, 2) MOCK rehearsal (no robot), 3) bring up CAN, 4) LIVE narrated run.
# Record this terminal next to the camera window (see docs/DEMO_GUIDE.md).
#
# Usage:   ./scripts/run_live_demo.sh           # interface defaults to can0
#          ./scripts/run_live_demo.sh can1
# ==========================================================================
set -e
cd "$(dirname "$0")/.."                      # repository root
IFACE="${1:-can0}"                           # CAN interface (default can0)
export PYTHONPATH=harness                    # import the harness modules

echo "== build C tools =="
make >/dev/null

echo "== rehearsal (MOCK, no robot): confirm the narration and IDS verdicts =="
python3 harness/live_demo.py mock

echo
echo "== bring up CAN interface $IFACE at 500 kbps =="
sudo modprobe gs_usb 2>/dev/null || true
sudo ip link set "$IFACE" down 2>/dev/null || true
sudo ip link set "$IFACE" up type can bitrate 500000
sudo ip link set "$IFACE" txqueuelen 1000
ip -details link show "$IFACE" | sed -n '1,3p'

echo
echo "== LIVE evidence run on $IFACE =="
echo "   Put the robot on its stand (wheels OFF the ground), e-stop in hand."
python3 harness/live_demo.py live --iface "$IFACE"
