import os,re,statistics,subprocess,sys,shutil,time
pat,guests,n,guest=sys.argv[1:5]; extra=sys.argv[5:]
d=os.environ.get("BENCH_DIR","/tmp/bench-runs"); os.makedirs(d,exist_ok=True)
acc={}; order=[]
for i in range(int(n)):
    out=f"{d}/m{i}"; shutil.rmtree(out,ignore_errors=True)
    t0=time.monotonic_ns()
    r=subprocess.run([pat,"run","--seed","1","--out",out]+(["--mount",f"{guests}:/guest"] if guests!="-" else [])+([] if guests=="-" else extra)+["--",(f"/guest/{guest}" if guests!="-" else guest)]+(extra if guests=="-" else []),stdout=subprocess.DEVNULL,stderr=subprocess.PIPE,text=True,env=dict(os.environ,PATINA_TEST_TIMING="1"))
    t1=time.monotonic_ns()
    ev=[("start",t0)]
    for l in r.stderr.splitlines():
        m=re.match(r"patina-mark (\S+) (\d+)",l)
        if m: ev.append((m.group(1),int(m.group(2))))
        m=re.match(r"patina-timing inc=0 (.*)",l)
        if m:
            kv=[x.split("=") for x in m.group(1).split()]
            ev+= [(k,int(v)) for k,v in kv]
    try:
        for l in open(f"{out}/inc-0/sandbox.log"):
            m=re.match(r"patina-mark (\S+) (\d+)",l)
            if m: ev.append(("sb-"+m.group(1),int(m.group(2))))
    except OSError: pass
    ev.sort(key=lambda e:e[1]); ev.append(("exit",t1))
    for (a,ta),(b,tb) in zip(ev,ev[1:]):
        k=f"{a}->{b}"
        if k not in acc: order.append(k)
        acc.setdefault(k,[]).append((tb-ta)/1e6)
    acc.setdefault("TOTAL",[]).append((t1-t0)/1e6)
    shutil.rmtree(out,ignore_errors=True)
for k in order+["TOTAL"]: print(f"  {k:28} {statistics.median(acc[k]):6.2f} ms")
