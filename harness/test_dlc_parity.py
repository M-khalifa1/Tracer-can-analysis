#!/usr/bin/env python3
"""Regression: mock candump and offline CSV must respect actual CAN DLC.

In particular 0x421 mode command is DLC=1 in real TRACER captures.
Safe: no SocketCAN calls; synthetic frames only.
"""
import csv
import pathlib
import tempfile
import unittest
import sys
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parent))
import canframes as C
import mock_bus
from candump2csv import main as convert

class DLCParityTests(unittest.TestCase):
    def test_mode_command_preserves_real_dlc_in_mock_and_offline(self):
        with tempfile.TemporaryDirectory(prefix='tracer_dlc_') as td:
            td=pathlib.Path(td)
            t=C.Trace()
            t.add_signed(100_000,C.MODE,bytes([1,0,0,0,0,0,0,0]),dlc=1)
            offline=td/'offline.csv'
            rows=t.write_csv(str(offline))
            self.assertTrue(any(cid==C.MODE and dlc==1 for _,cid,dlc,_ in rows))
            with offline.open(newline='') as fp:
                mode=[row for row in csv.DictReader(fp) if int(row['can_id'],16)==C.MODE]
            self.assertEqual(len(mode),1)
            self.assertEqual(mode[0]['dlc'],'1')
            self.assertEqual(mode[0]['data_hex'],'01')
            log=td/'mock.log'
            mock_bus.capture_log(rows,str(log))
            content=log.read_text()
            self.assertIn('421#01\n',content)
            self.assertNotIn('421#0100000000000000',content)
            captured=td/'captured.csv'
            convert(str(log),str(captured))
            with captured.open(newline='') as fp:
                mode_cap=[row for row in csv.DictReader(fp) if int(row['can_id'],16)==C.MODE]
            self.assertEqual(len(mode_cap),1)
            self.assertEqual(mode_cap[0]['dlc'],'1')
            self.assertEqual(mode_cap[0]['data_hex'],'01')

if __name__=='__main__': unittest.main(verbosity=2)
