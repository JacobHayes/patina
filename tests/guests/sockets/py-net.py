#!/usr/bin/python3
# Python socket + selectors: a non-blocking echo server driven by a selector, and
# client threads using blocking sockets with timeouts.
import selectors, socket, threading

sel = selectors.DefaultSelector()
lsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
lsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
lsock.bind(("127.0.0.1", 0))
lsock.listen()
lsock.setblocking(False)
port = lsock.getsockname()[1]
sel.register(lsock, selectors.EVENT_READ, None)

CLIENTS, MSGS = 8, 40
results = [None] * CLIENTS

def client(i):
    with socket.create_connection(("127.0.0.1", port), timeout=30) as c:
        c.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        total = 0
        for k in range(MSGS):
            msg = b"client %d message %03d\n" % (i, k)
            c.sendall(msg)
            back = b""
            while len(back) < len(msg):
                part = c.recv(len(msg) - len(back))
                assert part, "EOF"
                back += part
            assert back == msg
            total += sum(back)
        c.shutdown(socket.SHUT_WR)
        assert c.recv(10) == b""
        results[i] = total

threads = [threading.Thread(target=client, args=(i,)) for i in range(CLIENTS)]
for t in threads:
    t.start()
done = served = 0
while done < CLIENTS:
    for key, ev in sel.select(timeout=10):
        if key.data is None:
            conn, addr = lsock.accept()
            assert addr[0] == "127.0.0.1"
            conn.setblocking(False)
            sel.register(conn, selectors.EVENT_READ, b"")
            continue
        conn = key.fileobj
        data = conn.recv(4096)
        if not data:
            sel.unregister(conn)
            conn.close()
            done += 1
            continue
        served += len(data)
        conn.sendall(data)  # small replies: the send buffer has room
for t in threads:
    t.join()
# A receive timeout, and a refused connection.
s = socket.socket()
s.settimeout(1.5)
s.connect(("127.0.0.1", port))
try:
    s.recv(1)
    timed = False
except socket.timeout:
    timed = True
s.close()
lsock.close()
try:
    socket.create_connection(("127.0.0.1", port), timeout=5)
    refused = False
except ConnectionRefusedError:
    refused = True
print("py-net served %d checksum %d timeout %s refused %s" % (served, sum(results), timed, refused))
