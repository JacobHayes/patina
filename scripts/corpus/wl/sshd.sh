#!/bin/bash
# OpenSSH: sshd (non-root, own host key) on loopback; ssh runs commands and scp copies a file.
set -euo pipefail; shopt -s inherit_errexit
d=$PWD
ssh-keygen -q -t ed25519 -N '' -f $d/hk; ssh-keygen -q -t ed25519 -N '' -f $d/uk
cp $d/uk.pub $d/ak; chmod 600 $d/ak
cat > $d/sshd_config <<C
Port 41022
ListenAddress 127.0.0.1
HostKey $d/hk
PidFile $d/sshd.pid
AuthorizedKeysFile $d/ak
UsePAM no
StrictModes no
C
/usr/sbin/sshd -D -e -f $d/sshd_config 2>sshd.log & pid=$!
o="-i $d/uk -p 41022 -o StrictHostKeyChecking=no -o UserKnownHostsFile=$d/kh -o BatchMode=yes"
for i in $(seq 1 100); do ssh $o 127.0.0.1 true 2>/dev/null && break; sleep 0.1; done
ssh $o 127.0.0.1 'echo remote $((6*7)); uname -s'
seq 1 20000 > f; scp -O -q -P 41022 -i $d/uk -o StrictHostKeyChecking=no -o UserKnownHostsFile=$d/kh f 127.0.0.1:$d/g; cmp f g && echo scp-ok
kill $pid; wait $pid || true
