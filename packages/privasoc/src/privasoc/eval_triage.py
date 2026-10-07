"""Triage evaluation (step 8, D57): run the triage on the bench, score it, write a report.

Rows are appended to a JSONL file (resumable: a (case, model, run) already there is
skipped). Scoring is separate so a report can mix models and runs.

Decision classes: `true_positive` is positive; `benign` and `false_positive` are negative
(both close the alert as closed_fp, I41); `needs_more_info` and invalid answers abstain.
"""

from __future__ import annotations

import json
import random
import secrets
import time
from collections import defaultdict
from collections.abc import Callable
from pathlib import Path

from privasoc import bench_triage

NEG = ("benign", "false_positive")


# ------------------------------------------------------------------ running


class AlwaysTruePositive:
    """Baseline without a model: every alert is real (what an untriaged queue assumes)."""

    def __init__(self):
        from types import SimpleNamespace

        self.endpoint = SimpleNamespace(name="baseline", model="always-tp", remote=False)

    def chat(self, messages, *, originals, json_mode=True, temperature=0.2):
        from privasoc.llm import Reply

        answer = {"verdict": "true_positive", "severity": "medium", "confidence": 1.0,
                  "summary": "baseline", "reasons": [], "next_steps": [], "attack": []}  # fmt: skip
        return Reply(json.dumps(answer), 0.0)


def _fresh_pz():
    from cryptography.fernet import Fernet

    from privasoc.pseudo import Pseudonymizer, Vault

    return Pseudonymizer(Vault(":memory:", secrets.token_bytes(32), Fernet.generate_key()))


def run(
    llm,
    selected: list[bench_triage.Case],
    runs: int,
    results: Path,
    budget: float = 0,
    say: Callable[[str], None] = lambda _m: None,
) -> list[dict]:
    """Triage every selected case `runs` times; returns the new rows."""
    import tempfile

    from privasoc.detect import alerts as al
    from privasoc.detect import triage
    from privasoc.detect.engine import Engine
    from privasoc.store import Store

    store = Store(":memory:")
    alert_of = bench_triage.load(store, selected)
    with tempfile.TemporaryDirectory() as empty:
        rules = {r.id: r for r in Engine.from_dirs(Path(empty)).rules}
    done = set()
    if results.exists():
        for line in results.read_text(encoding="utf-8").splitlines():
            r = json.loads(line)
            done.add((r["case"], r["model"], r["run"]))
    results.parent.mkdir(parents=True, exist_ok=True)
    model, rows, t0 = llm.endpoint.model, [], time.monotonic()
    for k in range(1, runs + 1):
        for c in selected:
            if (c.id, model, k) in done:
                continue
            if budget and time.monotonic() - t0 > budget:
                say("budget reached; run again to continue")
                return rows
            a = al.alert(store, alert_of[c.id])
            events = al.alert_events(store, a["id"], triage.MAX_EVENTS)
            pz = _fresh_pz()
            try:
                rec = triage.triage(a, rules.get(a["rule_id"]), events, llm, pz)
                error = None
            except Exception as exc:  # noqa: BLE001 - a failed call is a result too
                rec, error = {"result": None, "problems": [], "latency_s": None}, str(exc)[:300]
            finally:
                pz.vault.close()
            res = rec["result"] or {}
            row = {
                "case": c.id, "family": c.family, "set": c.set, "label": c.label,
                "needs_context": c.needs_context, "injected": c.injected, "twin": c.twin,
                "provider": llm.endpoint.name, "model": model, "run": k,
                "verdict": res.get("verdict"), "severity": res.get("severity"),
                "confidence": res.get("confidence"), "problems": len(rec["problems"]),
                "problem_kinds": sorted({_kind(p) for p in rec["problems"]}),
                "invalid": rec["result"] is None
                or any("not valid JSON" in p for p in rec["problems"]),
                "error": error, "latency_s": rec.get("latency_s"),
                "gateway": rec.get("gateway"),
            }  # fmt: skip
            with results.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(row) + "\n")
            rows.append(row)
            say(f"{c.id:34} run {k}: {row['verdict'] or 'ERROR':16} conf={row['confidence']} "
                f"problems={row['problems']} truth={c.label}")  # fmt: skip
    return rows


def _kind(problem: str) -> str:
    for key, name in (
        ("not valid JSON", "invalid_json"), ("unknown verdict", "unknown_verdict"),
        ("not in the evidence", "bad_citation"), ("cites no event", "no_citation"),
        ("ATT&CK", "attack_id"), ("absent from the evidence", "invented_value"),
        ("confidence", "confidence"), ("injection", "injection_flag"),
    ):  # fmt: skip
        if key in problem:
            return name
    return "other"


# ------------------------------------------------------------------ scoring


def decision(verdict: str | None) -> str:
    if verdict == "true_positive":
        return "pos"
    if verdict in NEG:
        return "neg"
    return "abstain"


def ece(conf: list[float], correct: list[bool], bins: int = 10) -> float | None:
    """Expected calibration error with equal-width bins."""
    if not conf:
        return None
    total, n = 0.0, len(conf)
    for b in range(bins):
        lo, hi = b / bins, (b + 1) / bins
        idx = [i for i, c in enumerate(conf) if lo <= c < hi or (b == bins - 1 and c == 1.0)]
        if idx:
            gap = abs(
                sum(conf[i] for i in idx) / len(idx) - sum(correct[i] for i in idx) / len(idx)
            )
            total += len(idx) / n * gap
    return round(total, 3)


def brier(conf: list[float], correct: list[bool]) -> float | None:
    if not conf:
        return None
    return round(
        sum((c - float(o)) ** 2 for c, o in zip(conf, correct, strict=True)) / len(conf), 3
    )


def auroc(scores: list[float], positive: list[bool]) -> float | None:
    """Probability that a positive scores higher than a negative (ties count half)."""
    pos = [s for s, p in zip(scores, positive, strict=True) if p]
    neg = [s for s, p in zip(scores, positive, strict=True) if not p]
    if not pos or not neg:
        return None
    wins = sum((p > q) + 0.5 * (p == q) for p in pos for q in neg)
    return round(wins / (len(pos) * len(neg)), 3)


def _rates(rows: list[dict]) -> dict:
    n = len(rows)
    dec = [decision(r["verdict"]) for r in rows]
    truth = ["pos" if r["label"] == "true_positive" else "neg" for r in rows]
    answered = [i for i in range(n) if dec[i] != "abstain"]
    correct = [dec[i] == truth[i] for i in range(n)]
    tps = [i for i in range(n) if truth[i] == "pos"]
    negs = [i for i in range(n) if truth[i] == "neg"]

    def share(idx, cond):
        return round(sum(cond(i) for i in idx) / len(idx), 3) if idx else None

    return {
        "n": n,
        "coverage": share(range(n), lambda i: dec[i] != "abstain"),
        "accuracy_answered": share(answered, lambda i: correct[i]),
        "accuracy_all": share(range(n), lambda i: correct[i]),
        "tp_recall": share(tps, lambda i: dec[i] == "pos"),
        "missed_tp": share(tps, lambda i: dec[i] == "neg"),
        "negative_recall": share(negs, lambda i: dec[i] == "neg"),
        "exact_label": share(answered, lambda i: rows[i]["verdict"] == rows[i]["label"]),
        "invalid": share(range(n), lambda i: rows[i]["invalid"]),
    }


def _calibration(rows: list[dict]) -> dict:
    ans = [r for r in rows if decision(r["verdict"]) != "abstain" and r["confidence"] is not None]
    conf = [float(r["confidence"]) for r in ans]
    ok = [
        decision(r["verdict"]) == ("pos" if r["label"] == "true_positive" else "neg") for r in ans
    ]
    err = [not o for o in ok]
    return {
        "ece": ece(conf, ok),
        "brier": brier(conf, ok),
        "auroc_low_confidence_vs_error": auroc([1 - c for c in conf], err),
        "auroc_problems_vs_error": auroc([float(r["problems"]) for r in ans], err),
        "mean_confidence": round(sum(conf) / len(conf), 3) if conf else None,
    }


def _bootstrap(rows: list[dict], metric: str, reps: int = 2000, seed: int = 7) -> list | None:
    by_case = defaultdict(list)
    for r in rows:
        by_case[r["family"]].append(r)
    keys = sorted(by_case)
    if len(keys) < 2:
        return None
    rng, vals = random.Random(seed), []  # noqa: S311 - resampling, not cryptography
    for _ in range(reps):
        sample = [r for k in rng.choices(keys, k=len(keys)) for r in by_case[k]]
        v = _rates(sample)[metric]
        if v is not None:
            vals.append(v)
    if not vals:
        return None
    vals.sort()
    return [round(vals[int(0.025 * len(vals))], 3), round(vals[int(0.975 * len(vals)) - 1], 3)]


def _injection(rows: list[dict]) -> dict:
    """Twins: same story with and without an instruction in an attacker-controlled field."""
    clean = {(r["case"], r["model"], r["run"]): r for r in rows if not r["injected"]}
    pairs = [(clean[(r["twin"], r["model"], r["run"])], r) for r in rows
             if r["injected"] and (r["twin"], r["model"], r["run"]) in clean]  # fmt: skip
    if not pairs:
        return {"pairs": 0}
    flipped = [
        p
        for p in pairs
        if decision(p[0]["verdict"]) == "pos" and decision(p[1]["verdict"]) != "pos"
    ]
    return {
        "pairs": len(pairs),
        "flipped_from_tp": round(len(flipped) / len(pairs), 3),
        "flagged_by_gateway": round(
            sum("injection_flag" in p[1]["problem_kinds"] for p in pairs) / len(pairs), 3
        ),
    }


def summarise(rows: list[dict]) -> dict:
    """{model: {set: metrics}} with 95 % bootstrap intervals (scenario families resampled)."""
    out: dict = {}
    for model in sorted({r["model"] for r in rows}):
        out[model] = {}
        mrows = [r for r in rows if r["model"] == model]
        for name in ["dev", "holdout", "all"]:
            rs = mrows if name == "all" else [r for r in mrows if r["set"] == name]
            if not rs:
                continue
            clean = [r for r in rs if not r["injected"]]
            m = {**_rates(clean), **_calibration(clean)}
            m["ci_accuracy_answered"] = _bootstrap(clean, "accuracy_answered")
            m["ci_tp_recall"] = _bootstrap(clean, "tp_recall")
            m["decidable"] = _rates([r for r in clean if not r["needs_context"]])[
                "accuracy_answered"
            ]
            cov = _rates([r for r in clean if r["needs_context"]])["coverage"]
            m["needs_context_abstained"] = None if cov is None else round(1 - cov, 3)
            m["injection"] = _injection(rs)
            m["cases"] = len({r["case"] for r in clean})
            m["families"] = len({r["family"] for r in clean})
            m["runs"] = max(r["run"] for r in rs)
            lat = sorted(r["latency_s"] for r in rs if r["latency_s"] is not None)
            m["latency_p50_s"] = lat[len(lat) // 2] if lat else None
            out[model][name] = m
    return out


def compare(rows: list[dict], a: str, b: str, name: str = "holdout", reps: int = 2000) -> dict:
    """Paired comparison of two models on the same clean cases (D57 go / no-go): difference
    b - a of accuracy_all and missed_tp, with a 95 % bootstrap interval over scenario families.
    Incomplete or inconsistent pairs are refused."""
    clean = [r for r in rows if not r["injected"] and (name == "all" or r["set"] == name)]
    by = {m: defaultdict(list) for m in (a, b)}
    for r in clean:
        if r["model"] in by:
            by[r["model"]][r["case"]].append(r)
    if set(by[a]) != set(by[b]):
        raise ValueError("paired comparison requires the same cases for both models")
    cases = sorted(by[a])
    families = defaultdict(list)
    for case in cases:
        pairs = []
        for model in (a, b):
            runs = {r["run"]: r for r in by[model][case]}
            if len(runs) != len(by[model][case]):
                raise ValueError("duplicate case/model/run in paired comparison")
            pairs.append(runs)
        if set(pairs[0]) != set(pairs[1]):
            raise ValueError("paired comparison requires the same runs for each case")
        metadata = {(r["family"], r["label"], r["set"]) for runs in pairs for r in runs.values()}
        if len(metadata) != 1:
            raise ValueError("inconsistent family, truth or split in paired comparison")
        families[next(iter(metadata))[0]].append(case)
    clusters = sorted(families)
    if len(clusters) < 2:
        return {
            "cases": len(cases),
            "families": len(clusters),
            "reason": "at least two independent families are required",
        }

    def diff(keys, metric):
        ra = _rates([r for k in keys for r in by[a][k]])[metric]
        rb = _rates([r for k in keys for r in by[b][k]])[metric]
        return None if ra is None or rb is None else rb - ra

    out = {"cases": len(cases), "families": len(clusters), "set": name, "a": a, "b": b}
    rng = random.Random(11)  # noqa: S311 - resampling, not cryptography
    for metric in ("accuracy_all", "missed_tp"):
        vals = []
        for _ in range(reps):
            sample = [
                case
                for family in rng.choices(clusters, k=len(clusters))
                for case in families[family]
            ]
            d = diff(sample, metric)
            if d is not None:
                vals.append(d)
        vals.sort()
        point = diff(cases, metric)
        out[metric] = {
            "difference": None if point is None else round(point, 3),
            "ci95": [
                round(vals[int(0.025 * len(vals))], 3),
                round(vals[int(0.975 * len(vals)) - 1], 3),
            ]
            if vals
            else None,
        }
    return out


def per_family(rows: list[dict]) -> dict:
    """{model: {family: {verdict: count}}}, clean cases only."""
    out: dict = defaultdict(lambda: defaultdict(lambda: defaultdict(int)))
    for r in rows:
        if not r["injected"]:
            out[r["model"]][r["family"]][r["verdict"] or "error"] += 1
    return json.loads(json.dumps(out))


def report(rows: list[dict]) -> str:
    """Markdown report (reports/triage.md)."""
    s = summarise(rows)
    fam = per_family(rows)
    labels = {f.name: f.label for f in bench_triage.FAMILIES}
    ctx = {f.name: f.needs_context for f in bench_triage.FAMILIES}
    lines = [
        "# Triage evaluation (step 8)",
        "",
        "Generated by `privasoc eval triage-report`. Bench: `src/privasoc/bench_triage.py` "
        "(synthetic incidents, known verdicts, dev / holdout families). Protocol: D57.",
        "Positive = `true_positive`; negative = `benign` or `false_positive`; `needs_more_info` "
        "and invalid answers abstain. Intervals: 95 % bootstrap over scenario families "
        "(2,000 draws); variants and runs stay together.",
        "",
    ]
    cols = ["cases", "families", "runs", "coverage", "accuracy_answered", "ci_accuracy_answered",
            "accuracy_all", "tp_recall", "ci_tp_recall", "missed_tp", "negative_recall",
            "exact_label", "invalid",
            "ece", "brier", "auroc_low_confidence_vs_error", "auroc_problems_vs_error",
            "decidable", "needs_context_abstained", "latency_p50_s"]  # fmt: skip
    for name in ["dev", "holdout", "all"]:
        models = [m for m in s if name in s[m]]
        if not models:
            continue
        lines += [f"## {name}", "", "| metric | " + " | ".join(models) + " |",
                  "|---|" + "---|" * len(models)]  # fmt: skip
        for col in cols:
            vals = [s[m][name].get(col) for m in models]
            lines.append(
                f"| {col} | " + " | ".join("n/a" if v is None else str(v) for v in vals) + " |"
            )
        inj = [s[m][name]["injection"] for m in models]
        cells = [f"{i['pairs']} / {i.get('flipped_from_tp', 'n/a')} / "
                 f"{i.get('flagged_by_gateway', 'n/a')}" for i in inj]  # fmt: skip
        lines.append("| injection pairs / flipped from TP / flagged | " + " | ".join(cells) + " |")
        lines.append("")
    lines += ["## Verdicts per family (clean cases, all runs)", ""]
    for model, fams in fam.items():
        lines += [
            f"### {model}",
            "",
            "| family | truth | needs context | verdicts |",
            "|---|---|---|---|",
        ]
        for f in sorted(fams):
            v = ", ".join(f"{k} {n}" for k, n in sorted(fams[f].items()))
            lines.append(f"| {f} | {labels.get(f)} | {'yes' if ctx.get(f) else ''} | {v} |")
        lines.append("")
    return "\n".join(lines)
