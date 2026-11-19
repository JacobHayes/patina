// Deno.serve + 200 fetches (8 at a time), a Worker, file writes.
const ac = new AbortController();
const srv = Deno.serve({ port: 41099, hostname: '127.0.0.1', signal: ac.signal, onListen() {} }, async req => new Response('echo:' + new URL(req.url).pathname + ':' + (await req.text()).length));
const out: string[] = [];
for (let b = 0; b < 25; b++) out.push(...await Promise.all(Array.from({ length: 8 }, (_, j) => { const i = b * 8 + j; return fetch(`http://127.0.0.1:41099/r${i}`, { method: 'POST', body: 'x'.repeat(i) }).then(r => r.text()); })));
console.log('responses', out.length, out[199]);
const w = new Worker(`data:text/javascript,self.onmessage = e => { let s = 0; for (let i = 0; i < e.data; i++) s += i; self.postMessage(s); }`, { type: 'module' });
console.log('worker', await new Promise(ok => { w.onmessage = e => ok(e.data); w.postMessage(100000); })); w.terminate();
await Deno.writeTextFile('f.txt', 'x'.repeat(10000)); console.log('file', (await Deno.readTextFile('f.txt')).length);
ac.abort(); await srv.finished;
