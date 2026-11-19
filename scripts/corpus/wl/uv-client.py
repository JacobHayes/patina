import http.client, sys, time, concurrent.futures as cf
for _ in range(200):
    try:
        c = http.client.HTTPConnection('127.0.0.1', 41084, timeout=10); c.request('GET', '/'); c.getresponse().read(); break
    except OSError: time.sleep(0.05)
def run(k):
    c = http.client.HTTPConnection('127.0.0.1', 41084, timeout=10); out = []
    for i in range(25):
        c.request('POST', f'/r{k}-{i}', body=b'x' * i); out.append(c.getresponse().read())
    return out[-1]
with cf.ThreadPoolExecutor(4) as ex: print('replies', sorted(ex.map(run, range(4))))
