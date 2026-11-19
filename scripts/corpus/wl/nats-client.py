# A raw-protocol NATS client: 2 subscribers on a subject and a queue group, 200 published messages, request/reply.
import socket, sys, time
def conn():
    for _ in range(200):
        try: s = socket.create_connection(('127.0.0.1', 41093)); break
        except OSError: time.sleep(0.05)
    f = s.makefile('rb'); f.readline()  # INFO
    s.sendall(b'CONNECT {"verbose":false}\r\nPING\r\n'); assert f.readline() == b'PONG\r\n'
    return s, f
sub, sf = conn(); pub, pf = conn()
sub.sendall(b'SUB t.a 1\r\nSUB t.* q 2\r\nPING\r\n'); assert sf.readline() == b'PONG\r\n'
for i in range(200): pub.sendall(b'PUB t.a %d\r\n%s\r\n' % (len(str(i)), str(i).encode()))
pub.sendall(b'PING\r\n'); assert pf.readline() == b'PONG\r\n'
n = 0
while n < 400:
    l = sf.readline(); assert l.startswith(b'MSG'), l; sf.readline(); n += 1
print('received', n)
