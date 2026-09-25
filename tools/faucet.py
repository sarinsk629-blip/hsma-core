#!/usr/bin/env python3
# HSMA :: faucet.py - P2-11 (DEC-261): the decree faucet.
# Submits decree entries to a running epoch node and waits for the epoch
# header the node gossips back down the SAME socket (handle_decree sends
# to ALL peers - [R11]). Parses the DEFECT-184 layout: epoch@0(4)
# digest@4(4xu32) size@20(4) inner@24(4) weight@28(8) hash@36(4xu32)=52B.
#
# Usage: python3 tools/faucet.py [host] [port] [count] [--seed S] [--dupe]
#   --dupe  resends the first decree; the node must skip it (DEFECT-170 dedup;
#           visible in the node log as "[decree] duplicate entry - skipped")
import socket, struct, sys, time, argparse

MAGIC = b'HSMA'
T_EPOCH_HEADER, T_DECREE = 2, 3

def recv_exact(s, n):
    buf = b''
    while len(buf) < n:
        chunk = s.recv(n - len(buf))
        if not chunk: raise ConnectionError('peer closed')
        buf += chunk
    return buf

def recv_message(s):
    hdr = recv_exact(s, 9)
    if hdr[:4] != MAGIC: raise ValueError(f'bad magic {hdr[:4]!r}')
    plen = struct.unpack('>I', hdr[5:9])[0]
    return hdr[4], (recv_exact(s, plen) if plen else b'')

def main():
    ap = argparse.ArgumentParser(description='HSMA decree faucet')
    ap.add_argument('host', nargs='?', default='127.0.0.1')
    ap.add_argument('port', nargs='?', type=int, default=31233)
    ap.add_argument('count', nargs='?', type=int, default=10)
    ap.add_argument('--seed', type=int, default=0xC0FFEE)
    ap.add_argument('--dupe', action='store_true')
    a = ap.parse_args()

    print(f'[faucet] {a.host}:{a.port} | {a.count} decrees | seed {a.seed:#x}')
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(60)
    s.connect((a.host, a.port))
    print('[faucet] connected')

    digs = [struct.pack('>Q', (a.seed + i) * 0x9E3779B97F4A7C15 % (1<<64)) * 4
            for i in range(a.count)]
    for i, d in enumerate(digs):
        s.send(MAGIC + bytes([T_DECREE]) + len(d).to_bytes(4,'big') + d)
        print(f'[faucet] decree {i+1}/{a.count} sent')
        time.sleep(0.3)
    if a.dupe:
        d = digs[0]
        s.send(MAGIC + bytes([T_DECREE]) + len(d).to_bytes(4,'big') + d)
        print('[faucet] duplicate sent (node must skip - DEFECT-170)')

    print('[faucet] waiting for epoch header(s) on this socket...')
    t0 = time.time()
    seen = 0
    while time.time() - t0 < 45:
        try: mtype, payload = recv_message(s)
        except (socket.timeout, ConnectionError) as e:
            print(f'[faucet] socket ended ({type(e).__name__}) after {seen} header(s)')
            break
        if mtype == T_EPOCH_HEADER and len(payload) >= 52:
            epoch  = struct.unpack('>I', payload[0:4])[0]
            inner  = struct.unpack('>I', payload[24:28])[0]
            weight = struct.unpack('>Q', payload[28:36])[0]
            hsh = payload[36:52].hex()
            seen += 1
            print(f'[faucet] EPOCH HEADER #{seen}: epoch={epoch} inner={inner} '
                  f'weight={weight} hash={hsh[:16]}')
            print(f'[faucet] RECEIPT: {a.count} decrees -> epoch {epoch} completed, '
                  f'weight {weight} verified MACs, state hash {hsh[:16]}')
    if seen == 0:
        print('[faucet] TIMEOUT: no epoch header in 45s (mid-epoch fill? watch the node log)')
        s.close()
        return 1
    s.close()
    return 0

if __name__ == '__main__':
    sys.exit(main())
