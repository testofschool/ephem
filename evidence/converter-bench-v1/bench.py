#!/usr/bin/env python3
"""EPHEM converter benchmark harness (HANDOFF v2). Usage:
  python3 -I bench.py smoke|trackA|trackB [arm ...]
Writes raw CSV + JSON under /root/ephem-bench/evidence/converter-bench-v1/."""
import concurrent.futures as cf, csv, hashlib, json, math, os, subprocess, sys, time

B = "/root/ephem-bench"
EV = f"{B}/evidence/converter-bench-v1"
JAIL = f"{B}/ephem/target/ephem-jail"
NSJAIL = f"{B}/nsjail-src/nsjail"
PDFROOT = "/opt/ephem-bench/pdf-root"
FIXROOT = "/opt/ephem-bench/fixture-root"
FIXHOST = f"{B}/fixture-host"
FILES = [f"doc{i:02d}.pdf" for i in range(50)]
BASE_ENV = {"PATH": "/usr/bin:/bin"}


def pdf_cmd(arm, name):
    if arm == "raw":
        return ["/usr/bin/pdftotext", f"{B}/corpus/{name}", "-"], BASE_ENV
    if arm == "bwrap":
        return ["bwrap", "--unshare-all", "--uid", "65534", "--gid", "65534", "--ro-bind", PDFROOT, "/", "--tmpfs", "/tmp",
                "--die-with-parent", "/usr/bin/pdftotext", f"/in/{name}", "-"], BASE_ENV
    if arm == "nsjail":
        return [NSJAIL, "-Mo", "--chroot", PDFROOT, "-T", "/tmp", "-u", "65534", "-g", "65534", "--disable_proc", "--quiet",
                "--", "/usr/bin/pdftotext", f"/in/{name}", "-"], BASE_ENV
    if arm == "ephem":
        return [JAIL, "--root", PDFROOT, "--worker", "/usr/bin/pdftotext", "--", f"/in/{name}", "-"], \
            dict(BASE_ENV, EPHEM_GATE_PID=str(os.getpid()))
    if arm == "gvisor":
        return gv_cmd(gv_bundle(PDFROOT, ["/usr/bin/pdftotext", f"/in/{name}", "-"], name)), BASE_ENV
    raise SystemExit(f"unknown arm {arm}")


GV_TEMPLATE = f"{B}/gv/config.json"
import itertools
_gv_counter = itertools.count(1)


def gv_bundle(root, args, tag):
    """Pre-built OCI bundle per (root, args); built once, outside timing on first use is avoided by prewarm."""
    d = f"{B}/gv/bundles/{os.path.basename(root)}-{tag}"
    if not os.path.exists(f"{d}/config.json"):
        os.makedirs(d, exist_ok=True)
        c = json.load(open(GV_TEMPLATE))
        c["root"] = {"path": root, "readonly": True}
        c["process"]["args"] = args
        json.dump(c, open(f"{d}/config.json", "w"))
    return d


def gv_cmd(bundle):
    import threading
    cid = f"eb{os.getpid()}-{threading.get_ident() % 100000}-{next(_gv_counter)}"
    return ["runsc", "--network=none", "--ignore-cgroups", "run", "--bundle", bundle, cid]


def fix_cmd(arm):
    if arm == "gvisor":
        return gv_cmd(gv_bundle(FIXROOT, ["/worker"], "worker")), BASE_ENV
    if arm == "raw":
        return [FIXHOST], BASE_ENV
    if arm == "bwrap":
        return ["bwrap", "--unshare-all", "--uid", "65534", "--gid", "65534", "--ro-bind", FIXROOT, "/", "--tmpfs", "/tmp",
                "--die-with-parent", "/worker"], BASE_ENV
    if arm == "nsjail":
        return [NSJAIL, "-Mo", "--chroot", FIXROOT, "-T", "/tmp", "-u", "65534", "-g", "65534", "--disable_proc", "--quiet",
                "--", "/worker"], BASE_ENV
    if arm == "ephem":
        return [JAIL, "--root", FIXROOT, "--worker", "/worker"], dict(BASE_ENV, EPHEM_GATE_PID=str(os.getpid()))
    raise SystemExit(f"unknown arm {arm}")


def run(cmd, env, data=b""):
    t0 = time.perf_counter_ns()
    p = subprocess.run(cmd, input=data, env=env, capture_output=True, timeout=60)
    return time.perf_counter_ns() - t0, p


def nearest_rank(sorted_vals, q):
    return sorted_vals[max(1, math.ceil(q * len(sorted_vals))) - 1]


def track_a(arms):
    ref = {}
    for n in FILES:
        cmd, env = pdf_cmd("raw", n)
        _, p = run(cmd, env)
        ref[n] = hashlib.sha256(p.stdout).hexdigest()
    out = {"reference_arm": "raw", "arms": {}}
    for arm in arms:
        res = {"command_example": pdf_cmd(arm, "doc00.pdf")[0]}
        mism, first_err = [], None
        for n in FILES:  # equality pass (P8)
            cmd, env = pdf_cmd(arm, n)
            _, p = run(cmd, env)
            h = hashlib.sha256(p.stdout).hexdigest()
            if p.returncode != 0 or h != ref[n]:
                mism.append({"file": n, "rc": p.returncode, "sha256": h})
                if first_err is None:
                    first_err = p.stderr.decode(errors="replace")[:500]
        res["equal"] = 50 - len(mism)
        res["mismatches"] = mism[:10]
        res["first_error"] = first_err
        samples, bad = [], 0
        path = f"{EV}/raw/trackA_{arm}.csv"
        with open(path, "w", newline="") as fh:
            w = csv.writer(fh)
            w.writerow(["phase", "round", "file", "ns", "rc", "stdout_sha256"])
            for rnd in range(25):
                phase = "warmup" if rnd < 5 else "timed"
                for n in FILES:
                    cmd, env = pdf_cmd(arm, n)
                    ns, p = run(cmd, env)
                    h = hashlib.sha256(p.stdout).hexdigest()
                    w.writerow([phase, rnd, n, ns, p.returncode, h])
                    if phase == "timed":
                        samples.append(ns)
                        bad += (p.returncode != 0 or h != ref[n])
        s = sorted(samples)
        res["timed_runs"] = len(s)
        res["timed_runs_not_equal_or_rc_nonzero"] = bad
        res["ms"] = {k: round(nearest_rank(s, q) / 1e6, 3) for k, q in
                     [("p50", .50), ("p95", .95), ("p99", .99)]}
        res["ms"]["max"] = round(s[-1] / 1e6, 3)
        res["latency_reported"] = res["equal"] == 50 and bad == 0
        out["arms"][arm] = res
        print(arm, json.dumps({k: res[k] for k in ("equal", "timed_runs", "ms", "latency_reported")}), flush=True)
    return out


def pair(arm):
    cmd, env = fix_cmd(arm)
    _, d = run(cmd, env, b"DIRTY")
    _, c = run(cmd, env, b"CLEAN")
    return d.stdout.decode().strip(), c.stdout.decode().strip(), d.returncode, c.returncode


def track_b(arms):
    out = {}
    rows = []
    for arm in arms:
        modes = ["sequential"] if arm == "raw" else ["sequential", "concurrent8"]
        out[arm] = {}
        for mode in modes:
            if arm == "raw" and os.path.exists("/tmp/marker"):
                os.unlink("/tmp/marker")
            if mode == "sequential":
                results = [pair(arm) for _ in range(100)]
            else:
                with cf.ThreadPoolExecutor(8) as ex:
                    results = list(ex.map(lambda _: pair(arm), range(100)))
            for i, r in enumerate(results):
                rows.append([arm, mode, i, *r])
            out[arm][mode] = {
                "pairs": len(results),
                "dirty_written": sum(r[0] == "written" for r in results),
                "clean_present": sum(r[1] == "present" for r in results),
                "clean_absent": sum(r[1] == "absent" for r in results),
                "nonzero_rc": sum(r[2] != 0 or r[3] != 0 for r in results),
            }
            print(arm, mode, json.dumps(out[arm][mode]), flush=True)
        if arm == "raw" and os.path.exists("/tmp/marker"):
            os.unlink("/tmp/marker")
    with open(f"{EV}/raw/trackB_pairs.csv", "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["arm", "mode", "pair", "dirty_reply", "clean_reply", "dirty_rc", "clean_rc"])
        w.writerows(rows)
    return out


if __name__ == "__main__":
    mode, arms = sys.argv[1], sys.argv[2:]
    if mode == "smoke":
        for arm in arms:
            cmd, env = pdf_cmd(arm, "doc00.pdf")
            _, p = run(cmd, env)
            print("A", arm, p.returncode, hashlib.sha256(p.stdout).hexdigest(), p.stderr[:200])
            print("B", arm, pair(arm))
    elif mode == "trackA":
        json.dump(track_a(arms), open(f"{EV}/trackA.json", "w"), indent=1)
    elif mode == "trackB":
        json.dump(track_b(arms), open(f"{EV}/trackB.json", "w"), indent=1)
