"""
mock_bus.py — software stand-in for the robot's CAN bus, used ONLY to validate
the live pipeline on a machine without SocketCAN. It writes a real `candump -L`
format log containing (a) the scheduled host frames at their transmit times and
(b) synthetic chassis feedback the robot would emit (0x211/0x221/0x241/...), so
the exact same candump2csv + detector + scorer path that processes a real
capture is exercised end to end.

On the actual robot you do NOT use this — run_experiment.py `live` transmits via
AF_CAN (can_tx.py) and records with the real `candump`. The frame bytes are
identical; only the transport differs.
"""
import canframes as C

def _feedback_frames(span_us):
    """periodic chassis feedback the robot emits, mirroring observed cadence."""
    rows = []
    periodic = [(C.SYS,20000),(C.MOT_FB,20000),(C.RC,21000),(C.LIGHT_FB,100000),
                (C.HS_L,20000),(C.HS_R,20000),(C.LS_L,100000),(C.LS_R,100000),
                (C.ODO,50000)]
    for cid, per in periodic:
        t=0; k=0
        while t < span_us:
            pl = bytes([0xAA,0,0,0,0,0,0,k&0xFF]) if cid==C.RC else bytes([0,0,0,0,0,0,0,k&0xFF])
            rows.append((t, cid, pl)); t+=per; k+=1
    return rows

def capture_log(host_frames, out_log, base_wall=1_739_000_000.0):
    """Merge host frames (ts_us,id,dlc,bytes) with synthetic robot feedback and
    write a candump -L log. Returns out_log."""
    span = host_frames[-1][0] if host_frames else 0
    rows = [(ts, cid, bytes(pl)[:dlc]) for ts, cid, dlc, pl in host_frames]
    rows += _feedback_frames(span + 2_000_000)
    rows.sort(key=lambda r: r[0])
    with open(out_log, "w") as f:
        for ts_us, cid, pl in rows:
            wall = base_wall + ts_us/1e6
            hexs = ''.join('%02X' % b for b in pl)
            f.write("(%.6f) can0 %03X#%s\n" % (wall, cid, hexs))
    return out_log
