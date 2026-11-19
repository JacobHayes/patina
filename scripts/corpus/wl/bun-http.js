// Bun.serve + 200 fetches (8 at a time) + a Worker.
const srv = Bun.serve({ port: 41082, hostname: '127.0.0.1', fetch: async req => new Response('echo:' + new URL(req.url).pathname + ':' + (await req.text()).length) });
let out = [];
for (let b = 0; b < 25; b++) {
  out.push(...await Promise.all(Array.from({ length: 8 }, (_, j) => { const i = b * 8 + j; return fetch(`http://127.0.0.1:41082/r${i}`, { method: 'POST', body: 'x'.repeat(i) }).then(r => r.text()); })));
}
console.log('responses', out.length, out[199]);
const h = new Bun.CryptoHasher('sha256'); for (let i = 0; i < 2000; i++) h.update(String(i)); console.log('hash', h.digest('hex').slice(0, 8));
const proc = Bun.spawnSync(['/bin/echo', 'child']); console.log(proc.stdout.toString().trim());
srv.stop(true);
