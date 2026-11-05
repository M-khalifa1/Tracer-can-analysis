#!/usr/bin/env python3
"""Offline reproduction check with fresh detector replay in a temporary directory.
Preserves original capture, event labels and archived strict audit unchanged.
Required: make -B first. Does not open CAN interfaces or transmit frames.
"""
import collections,csv,hashlib,json,pathlib,subprocess,sys,tempfile
ROOT=pathlib.Path(__file__).resolve().parents[1]
PIN='5f7e2ca1ef2e55904fa1d68899dc65a5b65f27763f30254f282b22d8a8f46094'
EXPECTED={'NO_AUTH':5011,'BRUTE_FORCE':212,'VEL_JUMP':60,'BAD_MAC':58,'FLOOD':49,'STALE_SEQ':30,'UNKNOWN_ID':30,'BURST':3}
SCENARIOS={'A1':30,'A2':30,'A4':1,'A5':30,'A6':30,'A7':30,'A8':30,'A9':30}

def rows(p):
    with p.open(newline='',encoding='utf-8') as f:return list(csv.DictReader(f))

def main():
    cap=ROOT/'data/live_capture/exp_live_session.log'
    assert hashlib.sha256(cap.read_bytes()).hexdigest()==PIN,'physical capture hash mismatch'
    runner=ROOT/'bin/ids_runner'
    if not runner.is_file():raise SystemExit('First build from source: make -B')
    with tempfile.TemporaryDirectory(prefix='tracer-offline-') as t:
        tmp=pathlib.Path(t); fr=tmp/'frames.csv'; al=tmp/'alerts.csv'; audit=tmp/'audit.json'
        subprocess.run([sys.executable,str(ROOT/'harness/candump2csv.py'),str(cap),str(fr)],check=True)
        subprocess.run([str(runner),str(fr),str(al),'seq_window=64','require_auth_mode=1','suppress=0'],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        subprocess.run([sys.executable,str(ROOT/'harness/strict_capture_audit.py'),'--frames',str(fr),'--alerts',str(al),'--n','30','--out',str(audit)],check=False)
        a=json.loads(audit.read_text())
        assert len(rows(fr))==34419, 'wrong physical frame count'
        counts=collections.Counter(x['alert_type'] for x in rows(al))
        assert counts==EXPECTED,(counts,EXPECTED)
        assert a.get('status')=='FAIL', 'archived strict result unexpectedly changed; investigate original A5 fidelity'
        assert a.get('issues')==['A5: NOT a byte-for-byte replay of earlier seq=2 capture'],a.get('issues')
        assert a['benign']['frames_outside_attack_windows']==10414
        assert a['benign']['alerts_outside_attack_windows']==0
        for kind,num in SCENARIOS.items():
            assert a['attacks'][kind]['detected']==num,(kind,a['attacks'][kind]['detected'])
        archived=collections.Counter(x['alert_type'] for x in rows(ROOT/'results/archived_strict_frames_al.csv'))
        assert archived==counts,'replayed versus archived alert counts differ'
    print('PASS: capture checksum, fresh offline replay 34,419 frames, 5,453 alerts, 211/211 scripted alert matches')
    print('QUALIFICATION: original strict replay-fidelity check remains FAIL for A5, exactly as preserved')
    print('NOT CHECKED: live IDS latency, actuation, physical DoS, independent sessions or receiver enforcement')
if __name__=='__main__':main()
