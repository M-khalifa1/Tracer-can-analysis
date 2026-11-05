"""
can_tx.py — transmit a timed CAN frame schedule on a real SocketCAN interface,
using Linux AF_CAN raw sockets (no external tools). Used by run_experiment.py
for the LIVE run on the robot. The frame bytes are produced by canframes.py, the
SAME constructor validated offline against the C verifier, so a live frame is
byte-identical to the offline one.

This module only sends frames the operator explicitly scheduled, honours the
recorded inter-frame timing, and is import-safe on machines without SocketCAN
(the socket is opened lazily, only when send() is called).
"""
import socket, struct, time

CAN_FRAME_FMT = "=IB3x8s"   # can_id, can_dlc, pad(3), data(8)

def open_bus(iface):
    s = socket.socket(socket.AF_CAN, socket.SOCK_RAW, socket.CAN_RAW)
    s.bind((iface,))
    return s

def send_frame(sock, can_id, dlc, data8):
    payload = bytes(data8[:8]).ljust(8, b"\x00")
    frame = struct.pack(CAN_FRAME_FMT, can_id & 0x7FF, dlc & 0xF, payload)
    sock.send(frame)

def play_schedule(iface, frames, speed=1.0, progress=None):
    """frames: list of (ts_us, can_id, dlc, bytes). Transmit honouring the
    relative timing between ts_us values (scaled by 1/speed). Returns the list of
    (actual_send_wallclock_us, can_id) so the caller can align, though scoring
    uses the recorded candump, not this list."""
    sock = open_bus(iface)
    sent = []
    if not frames:
        return sent
    t0_us = frames[0][0]
    wall0 = time.monotonic()
    for ts_us, cid, dlc, data in frames:
        target = wall0 + (ts_us - t0_us) / 1e6 / max(speed, 1e-9)
        while True:
            now = time.monotonic()
            if now >= target:
                break
            time.sleep(min(0.0005, target - now))
        send_frame(sock, cid, dlc, data)
        sent.append((int(time.monotonic() * 1e6), cid))
        if progress:
            progress(ts_us, cid)
    sock.close()
    return sent
