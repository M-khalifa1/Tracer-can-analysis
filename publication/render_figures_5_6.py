#!/usr/bin/env python3
"""Independent figure reconstruction from the ARCHIVED offline alert CSV.
Results are written to publication/figures/reproduced/ to preserve the
exact manuscript image exports shipped under publication/figures/Fig.5/6.png.
This regenerates the underlying counts and timing; aesthetics may differ.
No CAN transmission or physical experiment is performed.
"""
import collections,csv,json,math
from pathlib import Path
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
ROOT=Path(__file__).resolve().parents[1]
alerts=ROOT/'results/archived_strict_frames_al.csv'
audit=ROOT/'results/archived_strict_audit.json'
frames=ROOT/'results/archived_strict_frames.csv'
out=ROOT/'publication/figures/reproduced'

def main():
    with alerts.open(newline='',encoding='utf-8') as f: rows=list(csv.DictReader(f))
    a=json.loads(audit.read_text())
    with frames.open(newline='',encoding='utf-8') as f: fr=list(csv.DictReader(f))
    assert len(rows)==5453 and len(fr)==34419
    count=collections.Counter(r['alert_type'] for r in rows)
    assert count=={'NO_AUTH':5011,'BRUTE_FORCE':212,'VEL_JUMP':60,'BAD_MAC':58,'FLOOD':49,'STALE_SEQ':30,'UNKNOWN_ID':30,'BURST':3}
    duration=max(int(row['ts_us']) for row in fr)/1e6
    assert 88.88<duration<88.90
    nbins=math.ceil(duration)
    auth=[0]*nbins;other=[0]*nbins
    for row in rows:
        ix=int(row['timestamp_us'])//1_000_000
        if ix>=nbins: continue
        (auth if row['alert_type']=='NO_AUTH' else other)[ix]+=1
    out.mkdir(parents=True,exist_ok=True)
    fig,ax=plt.subplots(figsize=(14,6))
    ax.step(range(nbins),auth,where='mid',label='NO_AUTH')
    ax.step(range(nbins),other,where='mid',label='All other categories')
    ax.set_yscale('symlog',linthresh=1);ax.set_xlim(0,duration)
    ax.set_xlabel('Elapsed time since start of archived physical capture (s)')
    ax.set_ylabel('Offline alert records per 1-second bin (symlog)')
    ax.set_title('Reconstructed offline IDS alert timeline')
    for name,v in a['attacks'].items():
        events=v['events']; start=min(e['t0_us'] for e in events)/1e6;end=max(e['t1_us'] for e in events)/1e6
        ax.axvspan(start,end,alpha=0.05)
        ax.text((start+end)/2,1.02,name,transform=ax.get_xaxis_transform(),ha='center',va='bottom',fontsize=8)
    ax.grid(alpha=0.18);ax.legend();fig.tight_layout();fig.savefig(out/'Fig.5.png',dpi=180);plt.close(fig)
    labels=[k for k,_ in count.most_common()];vals=[count[k] for k in labels]
    fig,ax=plt.subplots(figsize=(12,6));bar=ax.barh(labels[::-1],vals[::-1]);ax.set_xscale('log')
    ax.set_xlim(.8,max(vals)*2);ax.set_xlabel('Offline alert records (logarithmic scale)')
    ax.set_title('Offline IDS alerts by category (n=5,453)')
    for y,(name,val) in enumerate(reversed(list(zip(labels,vals)))):
        ax.text(val*1.07,y,f'{val:,} ({val/len(rows)*100:.2f}%)',va='center',fontsize=9)
    ax.grid(axis='x',alpha=.16);fig.tight_layout();fig.savefig(out/'Fig.6.png',dpi=180);plt.close(fig)
    print('PASS: 34,419 frames, 5,453 alerts; regenerated two diagnostic images in',out)
if __name__=='__main__':main()
