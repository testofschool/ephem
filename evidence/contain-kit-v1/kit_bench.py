#!/usr/bin/env python3
"""Contain-kit measurement: run common document converters under rootless confinement
(bubblewrap, nsjail, gVisor --rootless) as a non-root user, compare output with an
unconfined run, and time each call. Uses only the installed tools; no custom sandbox code.
Usage (as the non-root user): python3 -I kit_bench.py OUTDIR"""
import csv, hashlib, json, math, os, shutil, subprocess, sys, tempfile, time

K = "/opt/ephem-bench/kit"
IN = f"{K}/in"
NSJAIL = "/root/ephem-bench/nsjail-src/nsjail"
OUT = sys.argv[1]
os.makedirs(OUT, exist_ok=True)

# converter -> (argv builder given (in_dir, out_dir, name), list of inputs, rounds, compare mode)
def c_pdftotext(i, o, n): return ["/usr/bin/pdftotext", f"{i}/{n}", "-"]
def c_pdftoppm(i, o, n): return ["/usr/bin/pdftoppm", "-r", "150", "-png", "-singlefile", f"{i}/{n}", f"{o}/page"]
def c_tesseract(i, o, n): return ["/usr/bin/tesseract", f"{i}/{n}", "-"]
def c_qpdf(i, o, n): return ["/usr/bin/qpdf", "--check", f"{i}/{n}"]
def c_soffice(i, o, n): return ["/usr/bin/soffice", "--headless", "--norestore", "--convert-to", "pdf", "--outdir", o, f"{i}/{n}"]

PDFS = [f"doc0{k}.pdf" for k in range(10)]
PNGS = [f"page0{k}.png" for k in range(10)]
TXTS = [f"note0{k}.txt" for k in range(5)]
CONVERTERS = {
    "pdftotext (Poppler)": (c_pdftotext, PDFS, 10, "stdout"),
    "pdftoppm (Poppler)": (c_pdftoppm, PDFS, 10, "file:page.png"),
    "tesseract (OCR)": (c_tesseract, PNGS, 10, "stdout"),
    "qpdf --check": (c_qpdf, PDFS, 10, "stdout"),
    "soffice --convert-to pdf (LibreOffice)": (c_soffice, TXTS, 4, "file-text:note"),
}

BASE_ENV = {"PATH": "/usr/bin:/bin", "HOME": "/tmp", "LANG": "C.UTF-8"}

def wrap(arm, argv, outdir):
    if arm == "raw":
        return argv
    if arm == "bwrap":
        return ["bwrap", "--unshare-all", "--die-with-parent", "--new-session", "--clearenv",
                "--setenv", "PATH", "/usr/bin:/bin", "--setenv", "HOME", "/tmp", "--setenv", "LANG", "C.UTF-8",
                "--ro-bind", "/usr", "/usr", "--symlink", "usr/bin", "/bin", "--symlink", "usr/lib", "/lib",
                "--symlink", "usr/lib64", "/lib64", "--ro-bind", "/etc", "/etc", "--ro-bind", "/var/cache/fontconfig", "/var/cache/fontconfig",
                "--ro-bind", IN, IN, "--bind", outdir, outdir, "--tmpfs", "/tmp", "--proc", "/proc", "--dev", "/dev",
                "--"] + argv
    if arm == "nsjail":
        return [NSJAIL, "-Mo", "--quiet", "-R", "/usr", "-s", "usr/bin:/bin", "-s", "usr/lib:/lib", "-s", "usr/lib64:/lib64",
                "-R", "/etc", "-R", "/var/cache/fontconfig", "-R", "/dev/null", "-R", "/dev/urandom", "-R", IN, "-B", outdir, "-T", "/tmp",
                "-E", "PATH=/usr/bin:/bin", "-E", "HOME=/tmp", "-E", "LANG=C.UTF-8", "--time_limit", "60",
                "--"] + argv
    raise SystemExit(arm)

GV_STATE = tempfile.mkdtemp(prefix="gvs-")
GV_TEMPLATE = json.load(open(f"{K}/harness/gv_config.json"))
_gv = [0]

def gv_run(argv, outdir):
    _gv[0] += 1
    b = tempfile.mkdtemp(prefix="gvb-")
    c = json.loads(json.dumps(GV_TEMPLATE))
    # gVisor recipe: upload dir at /in (ro) and output dir at /out (rw) on a skeleton root
    c["process"]["args"] = [a.replace(outdir, "/out").replace(IN, "/in") for a in argv]
    c["mounts"] += [{"destination": "/in", "type": "bind", "source": IN, "options": ["rbind", "ro"]},
                    {"destination": "/out", "type": "bind", "source": outdir, "options": ["rbind", "rw"]}]
    c["process"]["user"] = {"uid": 0, "gid": 0}  # rootless: maps to the invoking non-root user
    json.dump(c, open(f"{b}/config.json", "w"))
    cmd = ["runsc", "--rootless", f"--root={GV_STATE}", "--network=none", "--ignore-cgroups", "--overlay2=root:memory", "run",
           "--bundle", b, f"kit{os.getpid()}-{_gv[0]}"]
    t0 = time.perf_counter_ns()
    p = subprocess.run(cmd, input=b"", env=BASE_ENV, capture_output=True, timeout=120)
    dt = time.perf_counter_ns() - t0
    shutil.rmtree(b, ignore_errors=True)
    return dt, p, cmd

def one(arm, build, name):
    outdir = tempfile.mkdtemp(prefix="kitout-", dir=f"{K}/scratch")
    argv = build(IN, outdir, name)
    if arm == "gvisor":
        dt, p, cmd = gv_run(argv, outdir)
    else:
        cmd = wrap(arm, argv, outdir)
        t0 = time.perf_counter_ns()
        p = subprocess.run(cmd, input=b"", env=BASE_ENV, capture_output=True, timeout=120)
        dt = time.perf_counter_ns() - t0
    return dt, p, outdir, cmd

def digest(mode, p, outdir):
    if mode == "stdout":
        # normalise the input path, which qpdf --check echoes (gVisor sees it as /in)
        out = p.stdout.replace(IN.encode() + b"/", b"<IN>/").replace(b"/in/", b"<IN>/")
        return hashlib.sha256(out).hexdigest()
    kind, prefix = mode.split(":")
    files = sorted(f for f in os.listdir(outdir) if f.startswith(prefix))
    if not files:
        return "NO_OUTPUT"
    path = f"{outdir}/{files[0]}"
    if kind == "file":
        return hashlib.sha256(open(path, "rb").read()).hexdigest()
    t = subprocess.run(["/usr/bin/pdftotext", path, "-"], capture_output=True).stdout
    return hashlib.sha256(t).hexdigest()

def nr(v, q):
    return v[max(1, math.ceil(q * len(v))) - 1]

def main():
    os.makedirs(f"{K}/scratch", exist_ok=True)
    arms = ["raw", "bwrap", "nsjail", "gvisor"]
    summary = {"uid": os.getuid(), "converters": {}}
    for cname, (build, inputs, rounds, mode) in CONVERTERS.items():
        ref = {}
        for n in inputs:
            _, p, od, _ = one("raw", build, n)
            ref[n] = digest(mode, p, od)
            shutil.rmtree(od, ignore_errors=True)
        cs = summary["converters"][cname] = {"inputs": len(inputs), "rounds": rounds, "compare": mode, "arms": {}}
        slug = cname.split()[0]
        with open(f"{OUT}/kit_{slug}.csv", "w", newline="") as fh:
            w = csv.writer(fh)
            w.writerow(["arm", "phase", "round", "input", "ns", "rc", "digest", "equal"])
            for arm in arms:
                times, eq, bad_rc, first_err, example = [], 0, 0, None, None
                for rnd in range(rounds + 1):
                    phase = "warmup" if rnd == 0 else "timed"
                    for n in inputs:
                        dt, p, od, cmd = one(arm, build, n)
                        d = digest(mode, p, od)
                        shutil.rmtree(od, ignore_errors=True)
                        ok = (p.returncode == 0 and d == ref[n])
                        w.writerow([arm, phase, rnd, n, dt, p.returncode, d, int(ok)])
                        example = example or cmd
                        if not ok and first_err is None:
                            first_err = f"rc={p.returncode} " + p.stderr.decode(errors="replace")[-300:]
                        if phase == "timed":
                            times.append(dt)
                            eq += ok
                            bad_rc += p.returncode != 0
                s = sorted(times)
                cs["arms"][arm] = {
                    "timed_runs": len(s), "equal_runs": eq, "nonzero_rc": bad_rc,
                    "p50_ms": round(nr(s, .5) / 1e6, 2), "p95_ms": round(nr(s, .95) / 1e6, 2),
                    "first_error": first_err, "example_cmd": example,
                }
                print(cname, arm, json.dumps({k: cs["arms"][arm][k] for k in ("timed_runs", "equal_runs", "p50_ms", "p95_ms")}), flush=True)
    json.dump(summary, open(f"{OUT}/kit_summary.json", "w"), indent=1)

main()
