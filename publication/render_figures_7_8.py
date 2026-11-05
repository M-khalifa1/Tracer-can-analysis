#!/usr/bin/env python3
"""Reproduce manuscript Figures 7 and 8 without requiring legacy Figure 9 evidence.
Only operates on archived numeric JSON; does not transmit CAN frames.
"""
import argparse
from pathlib import Path
from render_figures_7_9 import read_json, figure_7, figure_8
ROOT=Path(__file__).resolve().parents[1]
def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--check-only', action='store_true')
    parser.add_argument('--no-png', action='store_true')
    args=parser.parse_args()
    sweeps=read_json(ROOT/'results'/'sweeps.json')
    diag=read_json(ROOT/'results'/'validated_threshold_diagnostics.json')
    assert [r[0] for r in sweeps['flood_hz']['rows']]==[40,60,80,100,150,200,300,400]
    assert len(sweeps['vel_jump']['rows'])==13
    assert len(diag['r6_valid_companion'])==56
    assert len(diag['r6_missing_companion'])==7
    assert len(diag['r8_legitimate_resumption'])==49
    assert sum(bool(x['burst_false_alert']) for x in diag['r8_legitimate_resumption'])==28
    if args.check_only:
        print('PASS: Figure 7/8 inputs present and expected sweep dimensions match')
        return
    figure_7(sweeps,not args.no_png)
    figure_8(diag,not args.no_png)
    print('Regenerated Figures 7/8 from the preserved synthetic-test JSON files')
if __name__=='__main__':main()
