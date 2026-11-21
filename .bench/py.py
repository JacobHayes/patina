import os,re,statistics,subprocess,sys,shutil,time,json
pat,n=sys.argv[1],int(sys.argv[2]); cmd=sys.argv[3:]
d=os.environ.get("BENCH_DIR","/tmp/bench-runs"); os.makedirs(d,exist_ok=True)
ws=[];j=None
for i in range(n):
    out=f"{d}/p{i}"; shutil.rmtree(out,ignore_errors=True)
    t0=time.monotonic(); r=subprocess.run([pat,"run","--seed","1","--out",out]+cmd,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL); ws.append((time.monotonic()-t0)*1000)
    if i==0: j=json.load(open(f"{out}/result.json"))
    shutil.rmtree(out,ignore_errors=True)
c=j.get("compute",{}); print(f"{' '.join(cmd)[-60:]}: median {statistics.median(ws):.1f} ms min {min(ws):.1f}; traps {j.get('traps')} switches {j.get('switches')}")
