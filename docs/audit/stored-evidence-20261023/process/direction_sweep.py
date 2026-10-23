#!/usr/bin/env python3
"""direction-sweep: validate, rank and report a one-pass direction sweep.

Stdlib only. Subcommands:
  check  SWEEP.json          validate the ledger; exit 0 PASS, 1 FAIL, 2 unreadable input
  rank   SWEEP.json          deterministic elimination + ordering; prints JSON
  report SWEEP.json          markdown matrix for the user (runs check first)

The model never ranks candidates or decides eliminations by judgment: it fills the
ledger from primary sources and transcribes this script's output.
"""
import json
import sys
from datetime import datetime, timedelta, timezone

PREMISES = ["payer", "mechanism", "substitute", "reach", "input"]
# Importance order for "test first": money before mechanism before the rest.
# Rationale: the behaviour ladder cuts at money/workflow change (level 5); every
# other premise can hold while nobody pays.
VERDICTS = {"holds", "fails", "unknown", "contested"}
INCUMBENT_ANGLES = {"incumbent", "competitor"}
STATUSES = {"read", "blocked", "not_found", "not_attempted"}
TIERS = {"primary", "official", "news", "third_party", "self_report"}
KINDS = {"proposal", "substitute", "wait"}
KILL = {"dead", "wounded", "stood", "not_run"}
QUOTE_MAX = 300


def _dt(s):
    if not isinstance(s, str):
        return None
    try:
        d = datetime.fromisoformat(s.replace("Z", "+00:00"))
    except ValueError:
        return None
    return d if d.tzinfo is not None else None


def load(path):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError) as e:
        print(json.dumps({"error": f"cannot read {path}: {e}"}))
        sys.exit(2)


def check(d, now=None):
    errs = []
    now = now or datetime.now(timezone.utc)
    skew = timedelta(minutes=5)
    if d.get("schema") != "direction-sweep/1":
        errs.append("schema must be 'direction-sweep/1'")
    if not isinstance(d.get("question"), str) or not d["question"].strip():
        errs.append("question: non-empty string required")
    sl = d.get("success_line")
    if not isinstance(sl, dict) or sl.get("status") not in {"given", "minimum"} or not str(sl.get("text", "")).strip():
        errs.append("success_line: {text, status: given|minimum} required")
    swept = _dt(d.get("swept_at"))
    if swept is None:
        errs.append("swept_at: ISO datetime WITH timezone required")
    elif swept > now + skew:
        errs.append(f"R12: swept_at {d.get('swept_at')} is after the clock ({now.isoformat(timespec='minutes')}) — read the clock (`date`) and record the real time; a future-dated sweep proves no temporal order")
    cands = d.get("candidates")
    if not isinstance(cands, list) or not cands:
        errs.append("candidates: non-empty list required")
        return errs
    ids = [c.get("id") for c in cands if isinstance(c, dict)]
    if len(ids) != len(set(ids)) or None in ids:
        errs.append("candidates: every candidate needs a unique id")
    kinds = [c.get("kind") for c in cands if isinstance(c, dict)]
    if kinds.count("proposal") < 2:
        errs.append("R1: at least 2 proposals required (one proposal is a kill report, not a sweep)")
    if "substitute" not in kinds:
        errs.append("R1: a 'substitute' baseline (what the user would do anyway / free incumbent) is mandatory")
    if "wait" not in kinds:
        errs.append("R1: a 'wait' baseline (do nothing / wait for the next dated event) is mandatory")
    axes = {}
    for c in cands:
        if not isinstance(c, dict):
            errs.append("candidate must be an object")
            continue
        cid = c.get("id")
        if c.get("kind") not in KINDS:
            errs.append(f"{cid}: kind must be one of {sorted(KINDS)}")
        prov = str(c.get("provenance", ""))
        if not (prov == "requester" or prov == "designer" or prov.startswith("upstream:")):
            errs.append(f"{cid}: provenance must be requester | designer | upstream:<skill>")
        if c.get("kind") == "proposal":
            ax = str(c.get("axis", "")).strip().lower()
            if not ax:
                errs.append(f"{cid}: axis required for a proposal")
            elif ax in axes:
                errs.append(f"R2: {cid} shares axis '{ax}' with {axes[ax]} — merge or drop one before the kill round")
            else:
                axes[ax] = cid
            kill = c.get("kill", {})
            if not isinstance(kill, dict) or kill.get("verdict") not in KILL:
                errs.append(f"{cid}: kill.verdict must be one of {sorted(KILL)}")
            elif kill["verdict"] == "not_run":
                errs.append(f"R6: {cid}: kill round not run — every proposal is attacked in the same round")
            elif not str(kill.get("sentence", "")).strip():
                errs.append(f"{cid}: kill.sentence required (the killer's own sentence, or why it stood)")
            elif kill["verdict"] == "dead" and kill.get("angle") in INCUMBENT_ANGLES and not str(kill.get("adequacy_quote", "")).strip():
                errs.append(f"R11: {cid}: a death on an incumbent/competitor angle needs adequacy_quote (buyer evidence the incumbent is good enough); otherwise record 'wounded' and run differentiation-engine")
            elif kill["verdict"] == "dead":
                ks = str(kill.get("source", ""))
                if not str(kill.get("quote", "")).strip() or not (ks.startswith("http") or ks.startswith("file:")):
                    errs.append(f"R9: {cid}: a 'dead' kill eliminates only with the killing sentence quoted from a source — a death by ambiguity is recorded as 'wounded'")
        prem = c.get("premises")
        if not isinstance(prem, dict):
            errs.append(f"{cid}: premises object required")
            continue
        for p in PREMISES:
            x = prem.get(p)
            if not isinstance(x, dict):
                errs.append(f"R3: {cid}.{p}: missing — all five premises are assessed for every candidate")
                continue
            v, s = x.get("verdict"), x.get("status")
            if v not in VERDICTS:
                errs.append(f"{cid}.{p}: verdict must be holds|fails|unknown|contested")
            if v == "contested" and p != "substitute":
                errs.append(f"{cid}.{p}: 'contested' is only for the substitute slot (an incumbent exists, adequacy unproven)")
            if p == "substitute" and v == "fails" and not str(x.get("adequacy_quote", "")).strip():
                errs.append(f"R10: {cid}.substitute: 'fails' needs adequacy_quote — the buyer's own words, a measured switch/churn figure, or the deciding authority issuing the substitute itself, showing it is good enough; an incumbent merely existing is 'contested', which routes to differentiation-engine instead of eliminating")
            if s not in STATUSES:
                errs.append(f"{cid}.{p}: status must be one of {sorted(STATUSES)}")
            if not str(x.get("claim", "")).strip():
                errs.append(f"{cid}.{p}: claim text required")
            if v in {"holds", "fails", "contested"}:
                if s != "read":
                    errs.append(f"R4: {cid}.{p}: '{v}' requires status=read — a blocked or unread source can only be 'unknown'")
                src = str(x.get("source", ""))
                if not (src.startswith("http") or src.startswith("file:")):
                    errs.append(f"R4: {cid}.{p}: '{v}' requires a source URL or file: path")
                q = str(x.get("quote", "")).strip()
                if not q:
                    errs.append(f"R4: {cid}.{p}: '{v}' requires the governing sentence quoted from the source (a keyword hit is not a reading)")
                elif len(q) > QUOTE_MAX:
                    errs.append(f"{cid}.{p}: quote longer than {QUOTE_MAX} chars — quote the governing sentence only")
                if x.get("tier") not in TIERS:
                    errs.append(f"{cid}.{p}: tier must be one of {sorted(TIERS)}")
            if p == "payer" and c.get("kind") == "proposal":
                lvl = x.get("ladder_level")
                if not isinstance(lvl, int) or not 0 <= lvl <= 7:
                    errs.append(f"R5: {cid}.payer: ladder_level 0-7 required (0 = no observation)")
                elif v == "holds" and lvl < 5:
                    errs.append(f"R5: {cid}.payer: 'holds' needs ladder_level >= 5 (money or workflow change); level {lvl} is at most 'unknown'")
    # R7: a proposal may not survive on premises nobody tried to read. Without this, the least
    # researched candidate has the least evidence against it and wins by default (found in the
    # first behaviour run, 2026-09-25: a candidate with five 'unknown' slots, none attempted, ranked PICK).
    for c in cands:
        if not isinstance(c, dict) or c.get("kind") != "proposal" or not isinstance(c.get("premises"), dict):
            continue
        prem = c["premises"]
        dead = c.get("kill", {}).get("verdict") == "dead" if isinstance(c.get("kill"), dict) else False
        failed = any(isinstance(prem.get(p), dict) and prem[p].get("verdict") == "fails" for p in PREMISES)
        if dead or failed:
            continue
        for p in ("payer", "mechanism", "substitute"):
            x = prem.get(p)
            if isinstance(x, dict) and x.get("status") == "not_attempted":
                errs.append(f"R7: {c.get('id')}.{p}: a surviving proposal needs this slot attempted (read, blocked or not_found with the source tried) — unread is not the same as unrefuted")
            elif isinstance(x, dict) and x.get("status") in {"blocked", "not_found"} and not str(x.get("source", "")).strip():
                errs.append(f"R7: {c.get('id')}.{p}: record the source or query that was tried")
    pick = d.get("pick")
    if pick is not None:
        errs += check_pick(d, pick, swept, now)
    return errs


def check_pick(d, pick, swept, now=None):
    now = now or datetime.now(timezone.utc)
    skew = timedelta(minutes=5)
    errs = []
    if not isinstance(pick, dict):
        return ["pick must be an object or null"]
    r = rank(d)
    kinds = {c.get("id"): c.get("kind") for c in d.get("candidates", []) if isinstance(c, dict)}
    cand = pick.get("candidate")
    if r["verdict"] == "PICK":
        top = r["survivors"][0]["id"]
        if cand != top:
            errs.append(f"R8: pick.candidate must equal rank's top survivor ({top}); override needs a new sweep, not an edit")
    elif r["verdict"] == "TIE_ASK_USER":
        tied = [s["id"] for s in r["survivors"][:2]]
        if cand not in tied or pick.get("chosen_by") != "user":
            errs.append(f"R8: tie between {tied} — pick one of them with chosen_by='user'; the model does not break ties")
    elif kinds.get(cand) not in {"wait", "substitute"}:
        if r["verdict"] == "NO_PROPOSAL_BEATS_BASELINE":
            errs.append("R8: no surviving proposal sorts above both baselines — pick must be a baseline (wait/substitute) with a reopen criterion")
        else:
            errs.append("R8: no proposal survived — pick must be a baseline (wait/substitute) with a reopen criterion")
    kc = pick.get("kill_criterion")
    need = ["assumption", "cheapest_test", "pass_rule", "fail_rule", "stop_rule", "registered_at", "check_by"]
    if not isinstance(kc, dict):
        return errs + ["R8: pick.kill_criterion required"]
    for k in need:
        if not str(kc.get(k, "")).strip():
            errs.append(f"R8: kill_criterion.{k} required")
    reg, due = _dt(kc.get("registered_at")), _dt(kc.get("check_by"))
    if kc.get("registered_at") and reg is None:
        errs.append("R8: kill_criterion.registered_at needs a timezone")
    if kc.get("check_by") and due is None:
        errs.append("R8: kill_criterion.check_by needs a timezone")
    if reg and due and due <= reg:
        errs.append("R8: check_by must be after registered_at")
    if reg and reg > now + skew:
        errs.append(f"R12: kill_criterion.registered_at {kc.get('registered_at')} is after the clock — a pre-registration dated in the future proves no temporal order")
    if swept and reg and reg < swept:
        errs.append("R8: criterion registered before the sweep it belongs to")
    return errs


def rank(d):
    cands = [c for c in d.get("candidates", []) if isinstance(c, dict)]
    props = [c for c in cands if c.get("kind") == "proposal"]
    out, elim = [], []
    for c in props:
        prem = c.get("premises", {})
        fails = [p for p in PREMISES if isinstance(prem.get(p), dict) and prem[p].get("verdict") == "fails"]
        unknown = [p for p in PREMISES if isinstance(prem.get(p), dict) and prem[p].get("verdict") == "unknown"]
        contested = [p for p in PREMISES if isinstance(prem.get(p), dict) and prem[p].get("verdict") == "contested"]
        kv = c.get("kill", {}).get("verdict")
        if fails or kv == "dead":
            why = [f"premise '{p}' fails: {prem[p].get('quote','')}" for p in fails]
            if kv == "dead":
                why.append("killed: " + str(c.get("kill", {}).get("sentence", "")))
            elim.append({"id": c["id"], "label": c.get("label"), "reasons": why})
            continue
        out.append({"id": c["id"], "label": c.get("label"), "unknown": unknown, "contested": contested,
                    "kill": kv, "test_first": "substitute" if contested else (unknown[0] if unknown else None),
                    "route": "differentiation-engine" if contested else None,
                    "_key": (len(unknown) + len(contested), 0 if kv == "stood" else 1, c["id"])})
    out.sort(key=lambda x: x["_key"])
    # A baseline is what a proposal must beat: baselines sort by the same key and a proposal is
    # picked only if it sorts strictly above both. Baselines are never killed or eliminated; they
    # count as 'stood', and a baseline slot that 'fails' counts like 'unknown' (a free substitute
    # nobody pays for must not get harder to beat). Before 2026-09-28 baselines were consulted
    # only when no proposal survived, so an all-unknown 'wounded' proposal returned PICK.
    base = []
    for c in cands:
        if c.get("kind") not in {"substitute", "wait"}:
            continue
        prem = c.get("premises") if isinstance(c.get("premises"), dict) else {}
        unknown = [p for p in PREMISES if isinstance(prem.get(p), dict) and prem[p].get("verdict") == "unknown"]
        fails = [p for p in PREMISES if isinstance(prem.get(p), dict) and prem[p].get("verdict") == "fails"]
        base.append({"id": c.get("id"), "label": c.get("label"), "kind": c.get("kind"), "unknown": unknown,
                     "fails": fails, "test_first": unknown[0] if unknown else None,
                     "_key": (len(unknown) + len(fails), 0, str(c.get("id")))})
    base.sort(key=lambda x: x["_key"])
    verdict = "NO_SURVIVOR_STAY_WITH_BASELINE"
    if out and base and out[0]["_key"][:2] >= base[0]["_key"][:2]:
        verdict = "NO_PROPOSAL_BEATS_BASELINE"
    elif out:
        verdict = "PICK"
        if len(out) > 1 and out[0]["_key"][:2] == out[1]["_key"][:2]:
            verdict = "TIE_ASK_USER"
    for x in out + base:
        x.pop("_key")
    return {"verdict": verdict, "survivors": out, "baselines": base, "eliminated": elim}


def escape_grades(d):
    """Grade killer escapes: 'converged' only when >=2 non-designer candidates' killers named it.
    Rationale: a designer-authored candidate converging with another retrieves what was put in
    (kill-report-convergence step 2)."""
    prov = {c.get("id"): str(c.get("provenance", "")) for c in d.get("candidates", []) if isinstance(c, dict)}
    out = []
    for e in d.get("escapes", []) or []:
        if not isinstance(e, dict):
            continue
        names = [n for n in e.get("named_by", []) if n in prov]
        independent = [n for n in names if prov[n] != "designer"]
        out.append({"text": e.get("text", ""), "named_by": names,
                    "grade": "converged" if len(set(independent)) >= 2 else "single-source"})
    return out


def report(d):
    r = rank(d)
    mark = {"holds": "✓", "fails": "✕", "unknown": "?", "contested": "△"}
    lines = [f"# Direction sweep — {d.get('question')}", "",
             f"Success line ({d['success_line']['status']}): {d['success_line']['text']}",
             f"Swept at: {d.get('swept_at')}", "",
             "| Candidate | kind | " + " | ".join(PREMISES) + " | kill |",
             "|---|---|" + "---|" * len(PREMISES) + "---|"]
    for c in d["candidates"]:
        cells = [mark.get(c["premises"][p]["verdict"], "") for p in PREMISES]
        lines.append(f"| {c['id']} {c.get('label','')} | {c['kind']} | " + " | ".join(cells)
                     + f" | {c.get('kill',{}).get('verdict','—') if c['kind']=='proposal' else '—'} |")
    lines += ["", f"**Verdict: {r['verdict']}**", ""]
    for s in r["survivors"]:
        lines.append(f"- survivor {s['id']} {s['label']}: unknown = {s['unknown'] or 'none'}; test first = {s['test_first']}")
    for b in r["baselines"]:
        lines.append(f"- baseline {b['id']} {b['label']}: unknown = {b['unknown'] or 'none'}; fails = {b['fails'] or 'none'}")
    for e in r["eliminated"]:
        lines.append(f"- eliminated {e['id']} {e['label']}: " + " / ".join(e["reasons"]))
    grades = escape_grades(d)
    if grades:
        lines += ["", "Escapes named by killers (designer-authored candidates excluded from the count):"]
        for g in grades:
            lines.append(f"- [{g['grade']}] {g['text']} — named by {', '.join(g['named_by'])}")
    pk = d.get("pick")
    if pk:
        kc = pk["kill_criterion"]
        lines += ["", f"**Pick: {pk['candidate']}**",
                  f"- Riskiest assumption: {kc['assumption']}",
                  f"- Cheapest test: {kc['cheapest_test']}",
                  f"- Pass: {kc['pass_rule']} / Fail: {kc['fail_rule']} / Stop: {kc['stop_rule']}",
                  f"- Registered {kc['registered_at']}, check by {kc['check_by']}"]
    return "\n".join(lines)


def main(argv):
    if len(argv) != 3 or argv[1] not in {"check", "rank", "report"}:
        print(__doc__)
        return 2
    d = load(argv[2])
    if not isinstance(d, dict):
        print(json.dumps({"error": "top level must be an object"}))
        return 2
    errs = check(d)
    if argv[1] == "check":
        print(json.dumps({"result": "FAIL" if errs else "PASS", "errors": errs}, ensure_ascii=False, indent=1))
        return 1 if errs else 0
    if errs:
        print(json.dumps({"result": "FAIL", "errors": errs,
                          "note": "fix the ledger first; rank/report never run on an invalid ledger"}, ensure_ascii=False, indent=1))
        return 1
    if argv[1] == "rank":
        r = rank(d)
        r["escapes"] = escape_grades(d)
        print(json.dumps(r, ensure_ascii=False, indent=1))
    else:
        print(report(d))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
