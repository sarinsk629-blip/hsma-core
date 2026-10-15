#!/usr/bin/env python3
"""HSMA result decoder — turn a /result/{id} receipt into readable matrix values.
Usage:
  python3 decode_result.py <work_id> [--node URL]        # fetch + decode
  python3 decode_result.py --hex <hexstring> --n 8       # decode raw hex
"""
import sys, json, urllib.request

def decode_element(hex32):
    # canonical LE u64 limb 0 (values that fit in one limb decode exactly)
    return int.from_bytes(bytes.fromhex(hex32[:16]), "little")

def main():
    args = sys.argv[1:]
    if "--hex" in args:
        hx = args[args.index("--hex")+1]
        n = int(args[args.index("--n")+1]) if "--n" in args else 8
        raw = bytes.fromhex(hx)
    else:
        wid = args[0] if args else "1"
        node = args[args.index("--node")+1] if "--node" in args else "http://localhost:32234"
        data = json.loads(urllib.request.urlopen(f"{node}/result/{wid}").read().decode())
        print(f"work_id {data['work_id']} | status {data['status']} | verified: {data.get('verified')}")
        if "result" not in data:
            print("no result field (still processing?)"); sys.exit(1)
        raw = bytes.fromhex(data["result"])
        n = int((len(raw) // 32) ** 0.5)
    print(f"matrix C  ({n}x{n}), canonical LE decode:")
    print("+" + "--------+" * n)
    for i in range(n):
        row = []
        for j in range(n):
            off = (i*n + j) * 32
            v = int.from_bytes(raw[off:off+8], "little")
            row.append(f"{v:>8d}" if v < 10**8 else f"{v:>8x}")
        print("|" + "|".join(row) + "|")
    print("+" + "--------+" * n)
    print(f"tip: values >10^8 print in hex — full precision is in the raw hex above")

if __name__ == "__main__":
    main()
