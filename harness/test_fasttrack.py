#!/usr/bin/env python3
"""Non-mutating defensive regression tests for replay fidelity and event attribution."""
from __future__ import annotations
import csv, pathlib, tempfile, unittest, sys
import scenarios
import canframes as C
import mock_bus
import evaluate as E
import strict_capture_audit as S
from candump2csv import main as candump_convert


class VerifiedCaptureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp=tempfile.TemporaryDirectory(prefix='tracer_event_test_')
        p=pathlib.Path(cls.temp.name)
        cls.trace=scenarios.build_session(live=True,n=30)
        mock_bus.capture_log(cls.trace._materialise(),str(p/'capture.log'))
        candump_convert(str(p/'capture.log'),str(p/'fr.csv'))
        E.run_detector(str(p/'fr.csv'),{'seq_window':64,'require_auth_mode':1,'suppress':0})
        cls.frames_path=p/'fr.csv';cls.alerts_path=p/'fr_al.csv'
        cls.original_frames=S.load_frames(cls.frames_path)
        cls.original_alerts=S.load_alerts(cls.alerts_path)

    @classmethod
    def tearDownClass(cls): cls.temp.cleanup()

    def write_rows(self, rows, alerts=None):
        with tempfile.TemporaryDirectory(prefix='tracer_mutant_') as td:
            fr=pathlib.Path(td)/'f.csv'; al=pathlib.Path(td)/'a.csv'
            with fr.open('w',newline='') as f:
                w=csv.writer(f);w.writerow(('ts_us','can_id','dlc','data_hex'))
                for t,c,d in rows:w.writerow((t,f'0x{c:03X}',len(d),d.hex().upper()))
            with al.open('w',newline='') as f:
                w=csv.writer(f);w.writerow(('timestamp_us','alert_type'))
                for t,ty in (alerts if alerts is not None else self.original_alerts):w.writerow((t,ty))
            return S.audit(fr,al,30)

    def test_pass_exact_literal_replay(self):
        r=S.audit(self.frames_path,self.alerts_path,30)
        self.assertEqual('PASS',r['status'],r['issues'])
        self.assertEqual(30,r['attacks']['A5']['detected'])
        self.assertEqual([],r['attacks']['A5']['frame_shape_errors'])

    def test_deleted_a7_trial_fails(self):
        frames=self.original_frames
        phases=S.phase_groups([row for row in frames if row[1] in S.HOST_IDS])
        a7=phases[2+S.ATTACK_ORDER.index('A7')]
        removed={(t,c,d) for t,c,d in a7[8:12]}
        r=self.write_rows([f for f in frames if f not in removed])
        self.assertEqual('FAIL',r['status']);self.assertEqual(29,r['attacks']['A7']['reconstructed'])

    def test_deleted_a1_alert_fails(self):
        frames=self.original_frames
        phases=S.phase_groups([row for row in frames if row[1] in S.HOST_IDS])
        a1=phases[2]; target=a1[3][0]
        al=[(ts,typ) for ts,typ in self.original_alerts if not (typ=='NO_AUTH' and abs(ts-target)<60_000)]
        r=self.write_rows(frames,al)
        self.assertEqual('FAIL',r['status']);self.assertEqual(29,r['attacks']['A1']['detected'])

    def test_duplicate_a1_alert_not_double_counted(self):
        al=self.original_alerts
        duplicate=next(x for x in al if x[1]=='NO_AUTH')
        r=self.write_rows(self.original_frames,al+[duplicate])
        self.assertEqual(30,r['attacks']['A1']['detected'])

    def test_corrupt_literal_replay_source_fails(self):
        frames=list(self.original_frames)
        phases=S.phase_groups([row for row in frames if row[1] in S.HOST_IDS])
        a5=phases[2+S.ATTACK_ORDER.index('A5')]
        # last 60 frames = 30 event pairs; corrupt one authenticated companion
        sample=a5[-1]
        for ix,f in enumerate(frames):
            if f==sample:
                frames[ix]=(f[0],f[1],f[2][:-1]+bytes([f[2][-1]^1]));break
        r=self.write_rows(frames)
        self.assertEqual('FAIL',r['status']);self.assertTrue(any('A5:' in x for x in r['issues']))

    def test_extra_phase_fails(self):
        last=self.original_frames[-1][0]
        frames=list(self.original_frames)+[(last+3_000_000,0x666,b'\0'*8)]
        r=self.write_rows(frames)
        self.assertEqual('FAIL',r['status']);self.assertEqual(11,r['phase_count'])


if __name__=='__main__': unittest.main(verbosity=2)
