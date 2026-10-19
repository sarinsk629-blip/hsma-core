#!/usr/bin/env python3
"""gate_617_live.py — HSMA 6.17 v2 four-gate (CA-R281/317), persisted per CA-R299.
v3: key via GET /api_key (self-service bootstrap) + api_keys.txt fallback;
mint POST /submit_gemm INGESTED (explicit A/B) -> full byte-exact preimage loop;
claim checks: a/b == submitted hex, C == exact recompute, cross-/result, determinism.
v4 (s2): test_step52 in the test battery + GET /verifier leg — the rotating
epoch-verifier route must answer with the honest zero state on a fresh node
(n=8 mint never folds a claim; the pool is empty; has_receipt=false)."""
import glob, hashlib, json, os, re, signal, socket, subprocess, sys, time
import urllib.request, urllib.error

os.chdir(os.path.expanduser("~/hsma"))
HPP = "include/hsma/explorer.hpp"
REASONS = []

def src(): return open(HPP, errors="replace").read()
def sh(cmd, timeout=300):
    return subprocess.run(cmd, shell=True, text=True, capture_output=True, timeout=timeout)
def tail(path, n=15):
    try: return "".join(open(path, errors="replace").readlines()[-n:])
    except OSError: return "(no log)"
def port_open(port):
    try: socket.create_connection(("127.0.0.1", port), timeout=0.5).close(); return True
    except OSError: return False
def wait_log(pat, path, timeout, since=0):
    end = time.time() + timeout
    while time.time() < end:
        try:
            with open(path, errors="replace") as f:
                f.seek(since); data = f.read()
            m = re.search(pat, data)
            if m: return m
        except OSError: pass
        time.sleep(0.25)
    return None
def http(method, url, headers=None, body=None, timeout=15):
    req = urllib.request.Request(url, data=body.encode() if body else None, method=method)
    for k, v in (headers or {}).items(): req.add_header(k, v)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read().decode(errors="replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode(errors="replace")
    except Exception as e:
        return 0, repr(e)

# ---- gate 1: build ----
r = sh("ninja -C build")
print(f"[gate1 build] ninja rc={r.returncode}")
if r.returncode != 0:
    REASONS.append("build"); print(r.stdout[-1500:] + r.stderr[-1500:])

# ---- gate 2: tests ----
cands = ["test_step46", "test_step47", "test_step52", "t46", "t47", "t52"]
sh("ninja -C build " + " ".join(cands))
tests = [c for c in cands if os.path.isfile(f"build/{c}") and os.access(f"build/{c}", os.X_OK)]
print(f"[gate2 tests] binaries: {tests or 'NONE FOUND'}")
for i, t in enumerate(tests):
    errf = f"{t}_err.txt"
    r = sh(f"./build/{t} > {errf} 2>&1", timeout=900)
    print(f"[gate2 tests] {t} rc={r.returncode} -> {errf}")
    if r.returncode != 0:
        REASONS.append(f"tests:{t}"); print(tail(errf, 20))
if not tests:
    REASONS.append("tests: no binaries discovered")

# ---- gate 3: live ----
s = src()
mint_method, mint_path = None, None
lines = s.splitlines()
for idx, ln in enumerate(lines):
    if 'g_next_work_id.fetch_add' in ln:
        for j in range(idx, max(0, idx - 150), -1):
            m = (re.search(r'method == "(\w+)" && path\.rfind\("([^"]+)"', lines[j])
                 or re.search(r'method == "(\w+)" && path == "([^"]+)"', lines[j]))
            if m:
                mint_method, mint_path = m.group(1), m.group(2)
                break
        if mint_path: break
print(f"[gate3 live] mint route from source: {mint_method or '?'} {mint_path or '?'}")

nport = next((p for p in (31233, 31333, 31433) if not port_open(p)), None)
node = None
mark = os.path.getsize("node.log") if os.path.exists("node.log") else 0
try:
    if nport is None:
        REASONS.append("live: no free port")
    else:
        node = subprocess.Popen(["./build/epoch_node", str(nport)],
                                stdout=open("node.log", "ab"), stderr=subprocess.STDOUT,
                                start_new_session=True)
        m = wait_log(r"\[explorer\] HTTP server listening on port (\d+)", "node.log", 60, since=mark)
        if not m:
            REASONS.append("live: explorer never bound"); print(tail("node.log", 20))
        else:
            base = f"http://127.0.0.1:{m.group(1)}"
            print(f"[gate3 live] node up, explorer on :{m.group(1)}")

            # --- key bootstrap: GET /api_key (auth-free by design), file fallback ---
            keys = [os.environ["HSMA_API_KEY"]] if os.environ.get("HSMA_API_KEY") else []
            st, txt = http("GET", base + "/api_key")
            print(f"[gate3 live] GET /api_key -> {st} {txt[:110]}")
            if 200 <= st < 300:
                keys += re.findall(r'"(?:api_?key|key|token)"\s*:\s*"([^"]+)"', txt, re.I)
                if not keys:
                    keys += re.findall(r'"([A-Za-z0-9_-]{16,})"', txt)
            if os.path.exists("api_keys.txt"):
                for ln in open("api_keys.txt", errors="replace"):
                    ln = ln.strip()
                    if ln and not ln.startswith("#"):
                        keys += [t for t in re.split(r"[:\s,=]+", ln) if len(t) >= 16]
            keys = list(dict.fromkeys(keys))[:8]
            print(f"[gate3 live] keys available: {len(keys)}"
                  + (f" (first: {keys[0][:4]}***) " if keys else ""))

            # --- mint INGESTED: explicit small matrices, compact JSON (parser matches "a":" literally) ---
            wid, good_h = None, None
            n = 8
            A = [(k % 250) + 1 for k in range(n * n)]
            B = [(k % 13) + 1 for k in range(n * n)]
            AH = "".join(v.to_bytes(32, "little").hex() for v in A)
            BH = "".join(v.to_bytes(32, "little").hex() for v in B)
            EXP_C = [sum(A[i * n + k] * B[k * n + j] for k in range(n))
                     for i in range(n) for j in range(n)]
            mint_body = f'{{"n":{n},"a":"{AH}","b":"{BH}"}}'
            if not keys:
                REASONS.append("live: no API key")
            elif not mint_path:
                REASONS.append("live: mint route unparsed")
            else:
                for k in keys:
                    st, txt = http("POST", base + mint_path,
                                   headers={"Authorization": "Bearer " + k}, body=mint_body)
                    print(f"[gate3 live] mint POST {mint_path} (ingested n=8) -> {st} {txt[:110]}")
                    w = re.search(r'"work_id":(\d+)', txt)
                    if 200 <= st < 300 and w:
                        wid = int(w.group(1))
                        good_h = {"Authorization": "Bearer " + k}
                        break
                if wid is None:
                    REASONS.append("live: mint failed (auth or body rejected)")

            # --- wait VERIFIED, then claim + full preimage loop ---
            if wid is not None and good_h:
                if not wait_log(rf"\[work\] work_id {wid}: VERIFIED", "node.log", 240, since=mark):
                    REASONS.append(f"live: work {wid} never VERIFIED")
                else:
                    print(f"[gate3 live] work {wid} VERIFIED")
                    url = f"{base}/claim_inputs/{wid}"
                    st, txt = http("GET", url, headers=good_h)
                    print(f"[gate3 live] claim_inputs/{wid} -> {st} {txt[:110]}")
                    if st != 200:
                        REASONS.append(f"live: claim returned {st}"
                                       + (" — has_inputs/verified not set" if st == 404 else ""))
                    else:
                        try:
                            claim = json.loads(txt)
                            a_ok = claim["a"].lower() == AH
                            b_ok = claim["b"].lower() == BH
                            craw = bytes.fromhex(claim["c"])
                            C = [int.from_bytes(craw[i * 32:i * 32 + 8], "little")
                                 for i in range(n * n)]
                            c_ok = (len(craw) == n * n * 32 and C == EXP_C)
                            st2, r2 = http("GET", f"{base}/result/{wid}")
                            try: res_hex = json.loads(r2).get("result", "")
                            except Exception: res_hex = ""
                            cross = bool(res_hex) and res_hex.lower() == claim["c"].lower()
                            st3, txt3 = http("GET", url, headers=good_h)
                            det = (txt3 == txt)
                            print(f"[gate3 live] PREIMAGE byte-exact: a={a_ok} b={b_ok} "
                                  f"| C recompute={c_ok} | cross-/result={cross} | deterministic={det}")
                            print(f"[gate3 live] sha256(c)={hashlib.sha256(craw).hexdigest()}")
                            if not (a_ok and b_ok and c_ok and cross and det):
                                REASONS.append("live: preimage checks failed")
                        except Exception as e:
                            REASONS.append(f"live: preimage parse error {e!r}")

            # --- s2: the rotating epoch-verifier route (public, transparency) ---
            st4, txt4 = http("GET", f"{base}/verifier")
            print(f"[gate3 live] GET /verifier -> {st4} {txt4[:130]}")
            if st4 != 200:
                REASONS.append(f"live: /verifier returned {st4}")
            else:
                try:
                    v = json.loads(txt4)
                    schema_ok = all(kk in v for kk in (
                        "epoch", "rotations", "pool_size", "selected_work_id",
                        "identity_ok", "recompute_ran", "recompute_ok",
                        "pass", "has_receipt", "claim_identity"))
                    # honest zero state: this driver mints n=8 only — claims fold
                    # for n>64, so the pool is empty and no rotation has fired
                    zero_ok = (v.get("pool_size") == 0
                               and v.get("has_receipt") is False
                               and v.get("pass") is False
                               and v.get("rotations") == 0)
                    print(f"[gate3 live] verifier schema={schema_ok} zero_state={zero_ok} "
                          f"rotations={v.get('rotations')} pool={v.get('pool_size')}")
                    if not schema_ok:
                        REASONS.append("live: /verifier schema incomplete")
                    if not zero_ok:
                        REASONS.append("live: /verifier zero-state dishonest")
                except Exception as e:
                    REASONS.append(f"live: /verifier parse error {e!r}")
    # ---- gate 4: survival ----
    if node and node.poll() is None:
        time.sleep(8)
        soak = node.poll() is None
        with open("node.log", errors="replace") as f:
            f.seek(mark); fresh = f.read()
        clean = not re.search(r"FATAL|panic|Segmentation|Assertion", fresh)
        try:
            os.killpg(os.getpgid(node.pid), signal.SIGTERM); node.wait(timeout=20)
        except Exception:
            pass
        mark2 = os.path.getsize("node.log")
        node2 = subprocess.Popen(["./build/epoch_node", str(nport)],
                                 stdout=open("node.log", "ab"), stderr=subprocess.STDOUT,
                                 start_new_session=True)
        rebind = bool(wait_log(r"\[explorer\] HTTP server listening", "node.log", 60, since=mark2))
        try:
            os.killpg(os.getpgid(node2.pid), signal.SIGTERM); node2.wait(timeout=20)
        except Exception:
            pass
        print(f"[gate4 survival] soak_alive={soak} log_clean={clean} restart_rebind={rebind}")
        if not (soak and clean and rebind):
            REASONS.append("survival")
finally:
    if node and node.poll() is None:
        try: os.killpg(os.getpgid(node.pid), signal.SIGTERM)
        except Exception: pass
    sh("pkill -f 'build/epoch_node' 2>/dev/null")

print("=" * 52)
if REASONS:
    print("GATE617: RED — " + "; ".join(REASONS)); sys.exit(1)
print("GATE617: GREEN — build / tests / live / survival all pass")
