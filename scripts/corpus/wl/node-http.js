// An http server, a keep-alive client making 200 requests (8 concurrent), and 4 worker threads.
const http = require('http');
const { Worker, isMainThread, parentPort, workerData } = require('worker_threads');
const crypto = require('crypto');
if (!isMainThread) {
  let h = crypto.createHash('sha256');
  for (let i = 0; i < 2000; i++) h.update(String(workerData * 1e6 + i));
  parentPort.postMessage(h.digest('hex').slice(0, 8));
} else {
  const srv = http.createServer((req, res) => {
    let body = '';
    req.on('data', c => body += c);
    req.on('end', () => { res.setHeader('content-type', 'text/plain'); res.end('echo:' + req.url + ':' + body.length); });
  });
  srv.listen(41081, '127.0.0.1', async () => {
    const agent = new http.Agent({ keepAlive: true, maxSockets: 8 });
    const one = i => new Promise((ok, bad) => {
      const r = http.request({ host: '127.0.0.1', port: 41081, path: '/r' + i, method: 'POST', agent }, res => {
        let b = ''; res.on('data', c => b += c); res.on('end', () => ok(b));
      });
      r.on('error', bad); r.end('x'.repeat(i));
    });
    const out = await Promise.all(Array.from({ length: 200 }, (_, i) => one(i)));
    console.log('responses', out.length, out[199]);
    const ws = await Promise.all([1, 2, 3, 4].map(n => new Promise((ok, bad) => {
      const w = new Worker(__filename, { workerData: n }); w.on('message', ok); w.on('error', bad);
    })));
    console.log('workers', ws.join(','));
    const r = await fetch('http://127.0.0.1:41081/fetch'); console.log('fetch', r.status, await r.text());
    agent.destroy(); srv.close();
  });
}
