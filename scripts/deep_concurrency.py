# -*- coding: utf-8 -*-
"""deep_concurrency.py - concurrency and crash-injection checks.

1. two writers, same store: the FileLock must serialise them (or degrade with a
   clear timeout) and the store must stay fully parseable
2. concurrent readers during a write: gate lookups must never raise
3. hard kill mid-scan: no partial *.bundle.json may survive (atomic publish)
"""
import glob
import json
import os
import subprocess
import sys
import tempfile
import threading
import time

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PY = sys.executable
sys.path.insert(0, HERE)

def parse_all(store):
    bad = []
    for f in glob.glob(os.path.join(store, "attestations", "*.bundle.json")):
        try:
            json.load(open(f, encoding="utf-8"))
        except Exception as e:
            bad.append((os.path.basename(f), str(e)[:60]))
    return bad


def writer(out_dir, limit=3):
    code = (
        "import sys; sys.path.insert(0, r'%s')\n"
        "from canari.baseline import run_multi\n"
        "run_multi(npm_limit=0, pypi_limit=0, registry_limit=0, dsh_limit=%d, out_dir=r'%s')\n"
        % (HERE, limit, out_dir)
    )
    return subprocess.Popen([PY, "-c", code], stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, text=True)


def main():
    ok = True

    # ---- 1. concurrent writers on one store
    d = tempfile.mkdtemp(prefix="conc_")
    p1 = writer(d, 3)
    time.sleep(0.2)
    p2 = writer(d, 3)
    out1, _ = p1.communicate(timeout=300)
    out2, _ = p2.communicate(timeout=300)
    bad = parse_all(d)
    n = len(glob.glob(os.path.join(d, "attestations", "*.bundle.json")))
    lock_mentioned = ("lock" in (out2 or "").lower()) or ("TimeoutError" in (out2 or ""))
    print("[%s] concurrent writers: p1=%d p2=%d bundles=%d corrupt=%d lockmsg=%s"
          % ("PASS" if not bad and n > 0 else "FAIL",
             p1.returncode, p2.returncode, n, len(bad), lock_mentioned))
    ok &= not bad and n > 0

    # ---- 2. readers during a write
    store = os.path.join(HERE, "out")
    errors = []
    stop = threading.Event()

    def reader():
        from canari.consumer import list_components, latest_attestation
        while not stop.is_set():
            try:
                comps = list_components(store)
                if comps:
                    c = comps[0]
                    latest_attestation(store, c["registry"], c["name"])
            except Exception as e:
                errors.append(str(e)[:80])
                return
    threads = [threading.Thread(target=reader, daemon=True) for _ in range(8)]
    for t in threads:
        t.start()
    p3 = writer(store, 2)  # writes into the real store while 8 readers poll
    r3, _ = p3.communicate(timeout=300)
    stop.set()
    for t in threads:
        t.join(timeout=5)
    print("[%s] concurrent readers during write: errors=%d writer_rc=%d"
          % ("PASS" if not errors else "FAIL", len(errors), p3.returncode))
    ok &= not errors

    # ---- 3. hard kill mid-scan
    d2 = tempfile.mkdtemp(prefix="kill_")
    p4 = writer(d2, 40)
    time.sleep(3.0)
    p4.kill()
    p4.wait(timeout=30)
    time.sleep(1.0)
    bad2 = parse_all(d2)
    n2 = len(glob.glob(os.path.join(d2, "attestations", "*.bundle.json")))
    tmps = glob.glob(os.path.join(d2, "attestations", "*.tmp"))
    print("[%s] hard kill mid-scan: bundles=%d corrupt=%d leftover_tmp=%d"
          % ("PASS" if not bad2 else "FAIL", n2, len(bad2), len(tmps)))
    ok &= not bad2

    print("\n%s" % ("ALL CONCURRENCY CHECKS PASSED" if ok else "FAILURES PRESENT"))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
