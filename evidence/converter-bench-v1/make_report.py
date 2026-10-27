#!/usr/bin/env python3
"""Builds REPORT.md from evidence files; recomputes Track A percentiles from raw CSV
independently of bench.py's in-memory numbers and fails loudly on any disagreement."""
import csv, json, math, os, sys

EV = "/root/ephem-bench/evidence/converter-bench-v1"
A = json.load(open(f"{EV}/trackA.json"))
Bj = json.load(open(f"{EV}/trackB.json"))
obs = json.load(open(f"{EV}/p_observed.json"))
ARMS = ["raw", "bwrap", "nsjail", "ephem", "gvisor"]


def nr(v, q):
    return v[max(1, math.ceil(q * len(v))) - 1]


recheck = {}
for arm in ARMS:
    rows = list(csv.DictReader(open(f"{EV}/raw/trackA_{arm}.csv")))
    t = sorted(int(r["ns"]) for r in rows if r["phase"] == "timed")
    w = sum(r["phase"] == "warmup" for r in rows)
    ms = {k: round(nr(t, q) / 1e6, 3) for k, q in [("p50", .5), ("p95", .95), ("p99", .99)]}
    ms["max"] = round(t[-1] / 1e6, 3)
    recheck[arm] = (len(t), w, ms)
    if ms != A["arms"][arm]["ms"] or len(t) != A["arms"][arm]["timed_runs"]:
        sys.exit(f"RECOMPUTE MISMATCH {arm}: {ms} vs {A['arms'][arm]['ms']}")

L = []
L.append("# EPHEM converter benchmark v1 — REPORT (executed per HANDOFF v2)\n")
L.append(f"Host: Claude Code cloud session, x86_64, 2 vCPU, kernel 6.18.44, Ubuntu 24.04.5. Run start {obs['run_start']}. "
         "Nothing was committed, pushed, posted or sent.\n")
L.append("## 1. Pre-registered values\n")
L.append("| # | Item | Expected | Observed | Match |\n|---|---|---|---|---|")
for p in obs["P"]:
    L.append(f"| {p['id']} | {p['item']} | {p['expected']} | {p['observed']} | {p['match']} |")
L.append("\n## 2. Track A — `pdftotext` (pdftotext 24.02.0, same binary sha256 46e5639c… in every arm)\n")
L.append("Wall time from spawn to stdout EOF + reap, 50 files × 20 timed rounds after 5 warm-up rounds, run one at a time. "
         "Nearest-rank percentiles, recomputed from `raw/trackA_*.csv` by a second script (match).\n")
L.append("| Arm | Output equal to raw | Timed runs | p50 ms | p95 ms | p99 ms | max ms | Worker identity | Kernel |\n|---|---|---|---|---|---|---|---|---|")
ident = {"raw": "host uid 0", "bwrap": "uid 65534, userns", "nsjail": "uid 65534", "ephem": "uid 65534", "gvisor": "uid 65534"}
kern = {"raw": "host", "bwrap": "shared host kernel", "nsjail": "shared host kernel", "ephem": "shared host kernel",
        "gvisor": "user-space kernel (Sentry)"}
for arm in ARMS:
    r = A["arms"][arm]
    n, w, ms = recheck[arm]
    if r["latency_reported"]:
        L.append(f"| {arm} | {r['equal']}/50 | {n} | {ms['p50']} | {ms['p95']} | {ms['p99']} | {ms['max']} | {ident[arm]} | {kern[arm]} |")
    else:
        L.append(f"| {arm} | {r['equal']}/50 | {n} | — | — | — | — | {ident[arm]} | {kern[arm]} |")
L.append("\nNo arm is ranked. The arms differ in boundary: EPHEM, bwrap and nsjail share the host kernel; gVisor interposes a user-space kernel. "
         "EPHEM additionally applies seccomp (execve allowed once), Landlock, rlimits and drops all capabilities; the other arms were run with the flags in `commands.txt` only.\n")
L.append("## 3. Track B — cross-request residue (`/tmp/marker` written by DIRTY, probed by CLEAN)\n")
L.append("| Arm | Mode | Pairs | DIRTY `written` | CLEAN `present` | CLEAN `absent` | non-zero rc |\n|---|---|---|---|---|---|---|")
for arm in ARMS:
    for mode, r in Bj[arm].items():
        L.append(f"| {arm} | {mode} | {r['pairs']} | {r['dirty_written']} | {r['clean_present']} | {r['clean_absent']} | {r['nonzero_rc']} |")
e = Bj["ephem"]["concurrent8"]
L.append(f"\n**EPHEM concurrent (8 in flight) marker-crossing, the case the repo had not measured: {e['clean_present']}/{e['pairs']} present.**\n")
L.append("## 4. UNRUN and fallbacks taken\n")
for x in obs["unrun_fallbacks"]:
    L.append(f"- {x}")
L.append("\n## 5. Build-input changes\n")
for x in obs["build_changes"]:
    L.append(f"- {x}")
L.append("\n## 6. Limits of this result\n")
for x in obs["limits"]:
    L.append(f"- {x}")
open(f"{EV}/REPORT.md", "w").write("\n".join(L) + "\n")
print("REPORT OK; recompute matched for", ", ".join(ARMS))
