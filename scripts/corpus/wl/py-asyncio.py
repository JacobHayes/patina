# asyncio TCP echo server with 20 concurrent clients x 20 messages; then multiprocessing Pool(4) and a ThreadPool.
import asyncio, hashlib, multiprocessing as mp, concurrent.futures as cf, sys
async def handle(r, w):
    while data := await r.readline():
        w.write(data.upper()); await w.drain()
    w.close(); await w.wait_closed()
async def client(i):
    r, w = await asyncio.open_connection('127.0.0.1', 41083)
    got = []
    for j in range(20):
        w.write(f'c{i} m{j}\n'.encode()); await w.drain(); got.append(await r.readline())
    w.close(); await w.wait_closed()
    return len(got)
async def main():
    srv = await asyncio.start_server(handle, '127.0.0.1', 41083)
    n = await asyncio.gather(*(client(i) for i in range(20)))
    srv.close(); await srv.wait_closed()
    print('asyncio replies', sum(n))
def work(i):
    return hashlib.sha256(str(i).encode() * 1000).hexdigest()[:6]
if __name__ == '__main__':
    asyncio.run(main())
    for method in ('fork', 'spawn', 'forkserver'):
        with mp.get_context(method).Pool(4) as p:
            print(method, p.map(work, range(8))[-1])
    with cf.ThreadPoolExecutor(4) as ex:
        print('threads', list(ex.map(work, range(8)))[-1])
    q = mp.Queue(); ps = [mp.Process(target=q.put, args=(i,)) for i in range(4)]
    [p.start() for p in ps]; [p.join() for p in ps]; print('queue', sorted(q.get() for _ in range(4)))
