"""
scenarios.py — build ONE coherent experiment session (benign + every attack)
with EXACT ground-truth event timestamps, used identically by the offline replay
and the live-on-robot run. Same frame constructor both ways.

Timeline (gaps >= 2 s between phases so a capture is also human-auditable):
  benign -> A1 -> A2 -> A4(flood) -> A5(replay) -> A6(forged) -> A7(vjump)
         -> A8(brute) -> A9(unknown)

live=True omits synthetic chassis feedback (0x2xx/0x3xx): on the robot those
frames are emitted by the chassis itself and captured by candump. Only
host->robot command/attack frames are transmitted.
"""
import canframes as C

PHASE_GAP = 2_500_000
N = 30

def build_session(live=False, n=N):
    t = C.Trace()
    span_guess = 400_000_000
    if not live:
        # offline needs synthetic benign feedback for a realistic FPR denominator
        t.benign_feedback(0, span_guess)

    cur = 0
    # ---- benign phase: legitimate signed motion + mode changes ----
    t.benign_signed_mode(cur + 100_000, 0x01)
    t.benign_signed_ramp(cur + 300_000, vmax=800, step=40, hold_us=2_000_000)
    t.benign_signed_mode(cur + 6_000_000, 0x00)
    cur += 8_000_000

    def gap():
        return PHASE_GAP

    # ---- A1 unauthenticated motion x n ----
    cur += gap()
    for i in range(n):
        t.atk_unsigned_motion(cur + i * 200_000)
    cur += n * 200_000

    # ---- A2 mode hijack x n ----
    cur += gap()
    for i in range(n):
        t.atk_mode_hijack(cur + i * 200_000)
    cur += n * 200_000

    # ---- A4 flooding: one bounded 5 s session ----
    cur += gap()
    t.atk_flood(cur, dur_us=5_000_000, hz=1000)
    cur += 5_000_000

    # ---- A5 knowledgeable replay: advance seq with legit motion, then replay ----
    cur += gap()
    t.benign_signed_motion(cur, 2_000_000, lin=200)   # advances last_seq well past 2
    cur += 2_200_000
    for i in range(n):
        t.atk_replay_fresh(cur + i * 200_000, captured_seq=2)
    cur += n * 200_000

    # ---- A6 forged MAC x n (spaced so each is an isolated forgery) ----
    cur += gap()
    for i in range(n):
        t.atk_forged_mac(cur + i * 200_000)
    cur += n * 200_000

    # ---- A7 velocity jump x n ----
    cur += gap()
    for i in range(n):
        t.atk_vel_jump(cur + i * 300_000)
    cur += n * 300_000

    # ---- A8 MAC brute-force x n events (8 guesses each) ----
    cur += gap()
    for i in range(n):
        t.atk_brute_force(cur + i * 300_000, n=8)
    cur += n * 300_000

    # ---- A9 rogue/unknown node x n ----
    cur += gap()
    for i in range(n):
        t.atk_unknown_node(cur + i * 200_000)
    cur += n * 200_000

    return t
