#!/usr/bin/python3
# Python UDP: socket.SOCK_DGRAM client threads with timeouts and retry against a server
# thread; asyncio datagram endpoints (server and client protocols). `udp.py dns`:
# socket.getaddrinfo of localhost and of an unknown name.
import asyncio, socket, sys, threading

if sys.argv[1:] == ["dns"]:
    for name in ("localhost", "unknown.example"):
        try:
            print(name, sorted({a[4][0] for a in socket.getaddrinfo(name, 80)}))
        except socket.gaierror as e:
            print(name, "gaierror", e.errno, e.strerror)
    sys.exit(0)

srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
srv.bind(("127.0.0.1", 0))
port = srv.getsockname()[1]

def serve():
    while True:
        data, peer = srv.recvfrom(1500)
        if data == b"stop":
            return
        srv.sendto(data, peer)

resends = [0]
def client(i):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as c:
        c.connect(("127.0.0.1", port))
        c.settimeout(0.05)
        for k in range(20):
            msg = b"c%d m%02d" % (i, k)
            while True:
                c.send(msg)
                try:
                    if c.recv(64) == msg:
                        break
                except socket.timeout:
                    resends[0] += 1

t = threading.Thread(target=serve)
t.start()
clients = [threading.Thread(target=client, args=(i,)) for i in range(4)]
for c in clients:
    c.start()
for c in clients:
    c.join()
socket.socket(socket.AF_INET, socket.SOCK_DGRAM).sendto(b"stop", ("127.0.0.1", port))
t.join()

class Echo(asyncio.DatagramProtocol):
    def connection_made(self, tr):
        self.tr = tr
    def datagram_received(self, data, addr):
        self.tr.sendto(data, addr)

class Client(asyncio.DatagramProtocol):
    def __init__(self, done):
        self.done, self.got = done, []
    def connection_made(self, tr):
        for k in range(10):
            tr.sendto(b"a%d" % k)
    def datagram_received(self, data, addr):
        self.got.append(data)
        if len(self.got) == 10:
            self.done.set_result(sorted(self.got))
    def error_received(self, exc):
        self.done.set_exception(exc)

async def main():
    loop = asyncio.get_running_loop()
    st, _ = await loop.create_datagram_endpoint(Echo, local_addr=("127.0.0.1", 0))
    done = loop.create_future()
    ct, _ = await loop.create_datagram_endpoint(lambda: Client(done), remote_addr=st.get_extra_info("sockname"))
    got = await asyncio.wait_for(done, 5)
    # A connected endpoint to a port nobody holds: error_received gets ConnectionRefusedError.
    refused = loop.create_future()
    class Dead(asyncio.DatagramProtocol):
        def connection_made(self, tr):
            tr.sendto(b"x")
        def error_received(self, exc):
            refused.set_result(type(exc).__name__)
    dt, _ = await loop.create_datagram_endpoint(Dead, remote_addr=("127.0.0.1", 9))
    err = await asyncio.wait_for(refused, 5)
    for tr in (st, ct, dt):
        tr.close()
    return len(got), err

n, err = asyncio.run(main())
print("python udp: answers 80 resends", resends[0], "asyncio", n, err)
assert n == 10 and err == "ConnectionRefusedError"
