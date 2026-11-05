#!/usr/bin/env python3
"""
live_demo.py
==============================================================================
Narrated, screen-recordable evidence run for the TRACER 2.0 CAN-IDS paper.

This is the program you record in the terminal pane next to the camera. For
every attack it prints, in order:

  1) COMMAND   : exactly what is being transmitted on the bus,
  2) EXPECT    : the asserted IDS verdict AND the expected physical wheel effect,
  3) (live)    : the wheel speed decoded straight from the robot's CAN feedback,
  4) RESULT    : PASS/FAIL of the IDS assertion + the peak wheel speed observed.

So the recording shows three correlated pieces of evidence at once: the camera
(wheels turning), the decoded wheel speed (a number from the CAN bus), and the
IDS alert. That triangulation is what answers the reviewers.

Two modes
---------
  live  : on the real robot. Needs SocketCAN up on the interface. Transmits the
          attacks, reads feedback for wheel speed, and uses the real C IDS
          daemon (authoritative detection) running in the background.
  mock  : on any PC, no robot. The IDS verdict is still REAL (the frames are run
          through the same C detector), but wheel speed is marked [SIM] because
          only the physical robot can produce it. Use this to rehearse the
          layout before recording on the robot.

SAFETY (live): put the robot on a stand with the wheels OFF THE GROUND, keep the
RC emergency-stop in hand, and keep injected velocity <= 200 mm/s except the
single velocity-jump phase. The program pauses for you to confirm before moving.
==============================================================================
"""
import os, sys, time, json, argparse, subprocess, threading          # standard library only
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))       # allow importing our modules
import _paths                                        # repo layout (bin/, results/)
import canframes as C                                                # frame constructor (same as offline)
import canfeedback as FB                                             # wheel-speed decoder
import evaluate as E                                                 # reuse run_detector() for mock IDS

HERE = os.path.dirname(os.path.abspath(__file__))                    # directory of this script
OUT  = _paths.RESULTS; os.makedirs(OUT, exist_ok=True)# results directory

# ---- ANSI colours so the recorded pane is easy to read --------------------
BOLD="\033[1m"; GRN="\033[32m"; RED="\033[31m"; YEL="\033[33m"       # text styles
CYN="\033[36m"; MAG="\033[35m"; RST="\033[0m"                        # more styles + reset

def banner(txt, col=CYN):
    """Print a full-width labelled banner so each phase is obvious on video."""
    bar = "=" * 74                                                   # horizontal rule
    print(f"\n{col}{BOLD}{bar}\n{txt}\n{bar}{RST}")                  # coloured, bold block

# ==========================================================================
#  PHASE DEFINITIONS
#  Each phase: a human title, the COMMAND narration, the EXPECTED IDS alert(s),
#  the EXPECTED wheel effect text, and a builder that returns the list of
#  (ts_us, can_id, dlc, payload) frames to transmit for the demo.
#  Frames are built with canframes.Trace so they are byte-identical to the
#  offline/statistical runs.
# ==========================================================================
def _trace_to_frames(build):
    """Run a builder that fills a Trace, and return its time-sorted frames."""
    t = C.Trace()                                                   # fresh frame accumulator
    build(t)                                                        # let the phase add its frames
    return t._materialise()                                         # (ts_us,id,dlc,bytes) sorted

def phase_baseline(dur_s=3):
    """Legitimate SIGNED motion: the control case — wheels move, IDS stays silent."""
    def b(t):
        t.add_signed(100_000, C.MODE, bytes([0x01,0,0,0,0,0,0,0]), dlc=1)  # signed enter CAN mode
        t.benign_signed_motion(300_000, dur_s*1_000_000, lin=200)          # signed 200 mm/s stream
    return dict(title="BASELINE  legitimate SIGNED motion (control case)",
                command="send signed 0x421#01 then signed 0x111=200 mm/s + 0x112 companion",
                expect_ids=set(),                       # no alert expected (fully authenticated)
                expect_ids_txt="NO IDS alert (command is authenticated)",
                expect_wheel="wheels SPIN forward ~200 mm/s (legitimate motion)",
                frames=_trace_to_frames(b))

def phase_A1(n=15):
    """A1 unauthenticated motion: 0x111 with no companion -> NO_AUTH."""
    def b(t):
        for i in range(n): t.atk_unsigned_motion(200_000 + i*150_000, lin=200)
    return dict(title="A1  Unauthenticated motion injection",
                command="send 0x111=200 mm/s WITHOUT the 0x112 companion (x%d)" % n,
                expect_ids={"NO_AUTH"},
                expect_ids_txt="IDS fires NO_AUTH (unauthenticated command)",
                expect_wheel="wheels MAY spin ~200 mm/s IF the controller accepts "
                             "(detection-execution gap: often blocked by RC/timing)",
                frames=_trace_to_frames(b))

def phase_A7():
    """A7 velocity jump: signed 100 -> 1800 mm/s in one step -> VEL_JUMP (most visible)."""
    def b(t):
        t.add_signed(100_000, C.MODE, bytes([0x01,0,0,0,0,0,0,0]), dlc=1)   # signed CAN mode
        t.benign_signed_motion(300_000, 1_500_000, lin=100)                 # signed slow baseline
        t.atk_vel_jump(2_200_000, lo=100, hi=1800)                          # abrupt signed jump
    return dict(title="A7  Velocity-jump injection (most visible on camera)",
                command="signed baseline 100 mm/s, then abrupt 1800 mm/s in one 20 ms step",
                expect_ids={"VEL_JUMP"},
                expect_ids_txt="IDS fires VEL_JUMP (|delta| > 600 mm/s)",
                expect_wheel="wheels JUMP from slow to fast (~1800 mm/s target)",
                frames=_trace_to_frames(b))

def phase_A4():
    """A4 flooding DoS at ~1 kHz for 3 s -> FLOOD; legitimate control is starved."""
    def b(t): t.atk_flood(100_000, dur_us=3_000_000, hz=1000)
    return dict(title="A4  CAN-bus flooding (denial of service)",
                command="inject 0x111 at ~1000 Hz for 3 s (bus saturation)",
                expect_ids={"FLOOD"},
                expect_ids_txt="IDS fires FLOOD (rate > 200 Hz)",
                expect_wheel="wheels STUTTER/STOP: legitimate commands are delayed",
                frames=_trace_to_frames(b))

def phase_A5(n=10):
    """A5 knowledgeable replay: a valid signed pair resent with a stale seq -> STALE_SEQ."""
    def b(t):
        t.benign_signed_motion(100_000, 1_500_000, lin=200)        # advance last_seq well past 2
        for i in range(n): t.atk_replay_fresh(1_800_000 + i*150_000, captured_seq=2)
    return dict(title="A5  Knowledgeable replay (valid MAC, stale sequence)",
                command="capture a valid signed 0x111+0x112 pair, then retransmit it (x%d)" % n,
                expect_ids={"STALE_SEQ","REPLAY"},
                expect_ids_txt="IDS fires STALE_SEQ (freshness check rejects the replay)",
                expect_wheel="wheels may TWITCH toward the stale command briefly",
                frames=_trace_to_frames(b))

def phase_A6(n=10):
    """A6 forged authentication frame: 0x111 + 0x112 with a wrong 4-byte MAC -> BAD_MAC."""
    def b(t):
        for i in range(n): t.atk_forged_mac(200_000 + i*200_000, lin=200)
    return dict(title="A6  Forged authentication frame",
                command="send 0x111=200 mm/s + 0x112 with a wrong MAC 0xDEADBEEF (x%d)" % n,
                expect_ids={"BAD_MAC","BRUTE_FORCE"},
                expect_ids_txt="IDS fires BAD_MAC (MAC verification fails)",
                expect_wheel="passive IDS does not block, so wheels may move from the 0x111",
                frames=_trace_to_frames(b))

def phase_A2(n=10):
    """A2 mode hijack: unsigned 0x421#01 -> NO_AUTH (no direct wheel motion)."""
    def b(t):
        for i in range(n): t.atk_mode_hijack(200_000 + i*200_000, mode=0x01)
    return dict(title="A2  Control-mode hijack (unsigned 0x421)",
                command="send 0x421#01 (enter CAN mode) WITHOUT a companion (x%d)" % n,
                expect_ids={"NO_AUTH"},
                expect_ids_txt="IDS fires NO_AUTH (unauthenticated mode change)",
                expect_wheel="no direct motion: this only tries to seize control authority",
                frames=_trace_to_frames(b))

def phase_A8(n=6):
    """A8 brute-force: repeated wrong MACs -> BRUTE_FORCE escalation."""
    def b(t):
        for i in range(n): t.atk_brute_force(200_000 + i*250_000, n=8)
    return dict(title="A8  MAC brute-force (knowledgeable attacker)",
                command="repeatedly guess the 4-byte MAC (8 guesses x %d bursts)" % n,
                expect_ids={"BRUTE_FORCE","BAD_MAC"},
                expect_ids_txt="IDS escalates to BRUTE_FORCE after repeated failures",
                expect_wheel="no motion: all companions are invalid",
                frames=_trace_to_frames(b))

def phase_A9(n=10):
    """A9 rogue/unknown node: an ID outside the whitelist -> UNKNOWN_ID."""
    def b(t):
        for i in range(n): t.atk_unknown_node(200_000 + i*150_000, rogue=0x666)
    return dict(title="A9  Rogue node / unknown CAN ID",
                command="inject frames on ID 0x666 (not in the 14-entry whitelist) (x%d)" % n,
                expect_ids={"UNKNOWN_ID"},
                expect_ids_txt="IDS fires UNKNOWN_ID (identifier not whitelisted)",
                expect_wheel="no effect: the chassis ignores the rogue identifier",
                frames=_trace_to_frames(b))

# The demo order: control case first, then the attacks (visible ones early).
PHASES = [phase_baseline, phase_A1, phase_A7, phase_A4,
          phase_A5, phase_A6, phase_A2, phase_A8, phase_A9]

# Named phases so a single attack can be run in its own camera take
# (e.g. `--only A7`). Keys are the short attack labels used in the paper.
NAMED_PHASES = {
    "baseline": phase_baseline, "A1": phase_A1, "A2": phase_A2, "A4": phase_A4,
    "A5": phase_A5, "A6": phase_A6, "A7": phase_A7, "A8": phase_A8, "A9": phase_A9,
}

# ==========================================================================
#  LIVE transport: a background reader thread tracks wheel speed; the C IDS
#  daemon runs in the background and logs alerts we read after each phase.
# ==========================================================================
class LiveBus:
    """Owns the robot connection: a reader thread for wheel speed + the IDS daemon."""

    def __init__(self, iface):
        self.iface = iface                      # SocketCAN interface name, e.g. "can0"
        self.ws = FB.WheelState()               # live wheel-speed state
        self._stop = False                      # flag to end the reader thread
        self._reader = None                     # the reader Thread object
        self._daemon = None                     # the ids_daemon subprocess
        self._alog = os.path.join(OUT, "demo_live_alerts.csv")  # daemon alert log

    def start(self):
        import can_tx                            # AF_CAN helpers (import here: live only)
        import socket                            # raw CAN socket for the reader
        # 1) start the authoritative C IDS daemon in the background, logging alerts
        self._daemon = subprocess.Popen(
            ["sudo", _paths.binary("ids_daemon"), self.iface, self._alog],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        # 2) open a listening raw CAN socket and spin a thread to decode feedback
        self._sock = socket.socket(socket.AF_CAN, socket.SOCK_RAW, socket.CAN_RAW)
        self._sock.bind((self.iface,))          # receive every frame on the bus
        self._sock.settimeout(0.2)              # so the thread can check the stop flag
        self._reader = threading.Thread(target=self._read_loop, daemon=True)
        self._reader.start()                    # begin updating wheel speed
        time.sleep(1.0)                         # let the daemon attach before we inject

    def _read_loop(self):
        import struct                           # to unpack the 16-byte can_frame
        FMT = "=IB3x8s"                         # SocketCAN frame: id, dlc, pad, data
        while not self._stop:                   # until stop() is called ...
            try:
                frame = self._sock.recv(16)     # read one raw CAN frame (blocking w/ timeout)
            except Exception:
                continue                        # timeout: loop and re-check the stop flag
            cid, dlc, data = struct.unpack(FMT, frame)   # split into fields
            self.ws.update(cid & 0x7FF, data[:dlc])      # decode wheel speed if it is feedback

    def inject(self, frames):
        import can_tx                           # transmit the phase frames on the bus
        can_tx.play_schedule(self.iface, frames)# honours the recorded inter-frame timing

    def alert_count(self):
        """Return how many alert rows the IDS daemon has logged so far, by type."""
        counts = {}                             # {alert_type: count}
        if os.path.exists(self._alog):
            for ln in open(self._alog):
                if ln.startswith("timestamp") or ln.startswith("#"):
                    continue                    # skip header / suppression notes
                parts = ln.split(",")
                if len(parts) >= 2:
                    counts[parts[1]] = counts.get(parts[1], 0) + 1
        return counts

    def stop(self):
        self._stop = True                       # signal the reader thread to end
        if self._reader: self._reader.join(timeout=1.0)
        if self._daemon:                        # terminate the IDS daemon cleanly
            subprocess.run(["sudo","kill","-INT",str(self._daemon.pid)],
                           stderr=subprocess.DEVNULL)

# ==========================================================================
#  MOCK transport: no robot. IDS verdict is real (frames through ids_runner);
#  wheel speed is synthesised and clearly tagged [SIM].
# ==========================================================================
def mock_detect(frames):
    """Run one phase's frames through the SAME C detector and return alert types."""
    fcsv = os.path.join(OUT, "demo_mock_phase.csv")             # temp frame file
    with open(fcsv, "w") as f:                                  # write frames CSV
        f.write("ts_us,can_id,dlc,data_hex\n")
        for ts, cid, dlc, pl in frames:
            f.write("%d,0x%03X,%d,%s\n" % (ts, cid, dlc, ''.join('%02X'%b for b in pl)))
    alerts = E.run_detector(fcsv, {"seq_window":64,"require_auth_mode":1,"suppress":0})
    counts = {}                                                 # tally by type
    for _, ty in alerts:
        counts[ty] = counts.get(ty, 0) + 1
    return counts

# ==========================================================================
#  Run one phase and print the narrated evidence block.
# ==========================================================================
def run_phase(make, bus, mock):
    ph = make()                                                 # build the phase definition
    banner(ph["title"], CYN)                                    # big labelled header
    print(f"{BOLD}COMMAND:{RST} {ph['command']}")               # what we transmit
    print(f"{BOLD}EXPECT :{RST} {YEL}{ph['expect_ids_txt']}{RST}")       # expected IDS verdict
    print(f"{BOLD}       {RST} {YEL}{ph['expect_wheel']}{RST}")          # expected wheel effect
    input(f"{MAG}   press ENTER to launch this phase ...{RST}")  # operator gate (safety)

    if not mock:
        bus.ws.reset_peaks()                                    # clear per-phase wheel peaks
        before = bus.alert_count()                              # IDS alert tally before injecting
        # transmit while printing the live wheel speed a few times
        tx = threading.Thread(target=bus.inject, args=(ph["frames"],), daemon=True)
        tx.start()                                              # start transmitting in parallel
        while tx.is_alive():                                    # while the phase is transmitting ...
            print("   " + bus.ws.line(), end="\r", flush=True)  # live wheel-speed readout
            time.sleep(0.2)
        time.sleep(1.0)                                         # let final feedback/timeouts flush
        print("   " + bus.ws.line())                            # final wheel-speed line
        after = bus.alert_count()                               # IDS alert tally after
        # new alerts of each type produced during this phase
        got = {k: after.get(k,0)-before.get(k,0) for k in set(after)|set(before)}
        got = {k:v for k,v in got.items() if v>0}
        peak_lin, peak_rpm = bus.ws.peak_linear, bus.ws.peak_rpm
    else:
        got = mock_detect(ph["frames"])                         # REAL IDS verdict, no robot
        peak_lin = peak_rpm = None                              # wheel speed only on the robot

    # ---- assertion: did the expected IDS alert fire? ----
    exp = ph["expect_ids"]                                      # set of acceptable alert types
    if not exp:                                                 # baseline: expect NO alert
        ok = (sum(got.values()) == 0)
        verdict = "PASS (no alert on legitimate traffic)" if ok else "CHECK (unexpected alert)"
    else:
        ok = any(got.get(a,0) > 0 for a in exp)                 # any acceptable alert present?
        verdict = "PASS" if ok else "FAIL"
    col = GRN if ok else RED                                    # green pass / red fail
    print(f"{BOLD}RESULT :{RST} {col}IDS assertion {verdict}{RST}  alerts={got or 'none'}")
    if peak_lin is not None:                                    # live: report the wheel evidence
        print(f"         wheel evidence: peak linear={peak_lin} mm/s, peak motor={peak_rpm} RPM")
    else:                                                       # mock: wheel speed not available
        print(f"         wheel evidence: {YEL}[SIM] measured live on the robot{RST}")
    return ph["title"], ok, got, (peak_lin, peak_rpm)

def main():
    ap = argparse.ArgumentParser(description="Narrated live/mock evidence run")
    ap.add_argument("mode", choices=["live","mock"])            # which transport
    ap.add_argument("--iface", default="can0")                 # SocketCAN interface for live
    ap.add_argument("--only", default=None,                    # run ONE phase in its own take
                    help="run a single phase for an individual camera take, "
                         "e.g. --only A7 (choices: " + ",".join(NAMED_PHASES) + ")")
    ap.add_argument("--list", action="store_true",             # list phases and exit
                    help="list the available phases and exit")
    args = ap.parse_args()

    if args.list:                                              # just print the phase names
        print("Available phases (use with --only):")
        for name in NAMED_PHASES:
            print("  ", name)
        return

    # Pick the phases to run: one named phase for a per-attack take, or all.
    if args.only:
        if args.only not in NAMED_PHASES:                      # guard against a typo
            print("unknown phase:", args.only, "| choices:", ", ".join(NAMED_PHASES)); return
        phases = [NAMED_PHASES[args.only]]
    else:
        phases = PHASES                                        # the full sequential run

    banner("TRACER 2.0 CAN-IDS — live evidence run (%s mode)" % args.mode.upper(), MAG)
    if args.mode == "live":
        print(f"{RED}{BOLD}SAFETY:{RST} wheels OFF the ground, RC e-stop in hand, "
              f"velocity <=200 mm/s except the A7 jump.")
        input(f"{MAG}   confirm the robot is on a stand, then press ENTER ...{RST}")
        bus = LiveBus(args.iface); bus.start()                 # start reader + IDS daemon
    else:
        bus = None                                             # no robot in mock mode

    summary = []                                               # collect per-phase results
    try:
        for make in phases:                                    # walk the selected phase(s) in order
            summary.append(run_phase(make, bus, args.mode=="mock"))
    finally:
        if bus: bus.stop()                                     # always clean up the robot link

    # ---- final scorecard for the recording ----
    banner("SUMMARY", MAG)
    for title, ok, got, wheel in summary:
        mark = f"{GRN}PASS{RST}" if ok else f"{RED}FAIL{RST}"
        print(f"  [{mark}] {title[:46]:46s} alerts={got or 'none'}")
    npass = sum(1 for _,ok,_,_ in summary if ok)               # how many assertions passed
    print(f"\n  {npass}/{len(summary)} IDS assertions passed")
    json.dump([{ "title":t, "pass":ok, "alerts":g } for t,ok,g,_ in summary],
              open(os.path.join(OUT, f"demo_{args.mode}_summary.json"),"w"), indent=2)

if __name__ == "__main__":
    main()
