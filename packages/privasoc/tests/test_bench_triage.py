"""Step 8 (D57): the triage bench, its scoring, and the evidence fixes found with it (I42)."""

import json
import secrets
import threading
from collections import Counter
from http.server import BaseHTTPRequestHandler, HTTPServer

from cryptography.fernet import Fernet

from privasoc import bench_triage as b
from privasoc import eval_triage as e
from privasoc.detect import alerts as al
from privasoc.detect import triage
from privasoc.pseudo import Pseudonymizer, Vault
from privasoc.store import Store


def _pz():
    return Pseudonymizer(Vault(":memory:", secrets.token_bytes(32), Fernet.generate_key()))


def test_every_scenario_raises_exactly_its_alert():
    cases = b.cases()
    store = Store(":memory:")
    found = b.load(store, cases)  # raises on a missing or unexpected alert
    assert len(found) == len(cases) == 38
    for c in cases:
        assert al.alert(store, found[c.id])["title"] == c.rule


def test_split_is_balanced_and_deterministic():
    fams = Counter((f.set, f.label) for f in b.FAMILIES)
    for s in ("dev", "holdout"):
        assert fams[(s, "true_positive")] == 4
        assert fams[(s, "benign")] == 2 and fams[(s, "false_positive")] == 2
    assert [c.events for c in b.cases()] == [c.events for c in b.cases()]
    assert len({c.sender for c in b.cases()}) == 38


def test_injection_survives_only_in_free_text_fields():
    cases = {c.id: c for c in b.cases()}
    store = Store(":memory:")
    found = b.load(store, list(cases.values()))

    def prompt(cid):
        a = al.alert(store, found[cid])
        return triage.build_evidence(a, None, al.alert_events(store, a["id"], 20), _pz())[0]

    assert "ignore all previous instructions" in prompt("W1-web-tool-scan-v1-inj")
    # identity fields are pseudonymised: the instruction does not reach the model
    assert "ignore" not in prompt("S1-ssh-dictionary-v1-inj").lower()
    assert "ignore" not in prompt("D1-dns-tunnel-v1-inj").lower()


def test_alert_detail_keys_are_not_pseudonymised():
    store = Store(":memory:")
    c = next(c for c in b.cases() if c.id == "F1-fw-external-scan-v1")
    found = b.load(store, [c])
    a = al.alert(store, found[c.id])
    p = triage.build_evidence(a, None, al.alert_events(store, a["id"], 20), _pz())[0]
    assert '"source.ip"' in p


def test_propagation_does_not_rewrite_tokens():
    out = Pseudonymizer.propagate(
        "invalid user user-bc63be from x", {"user": "user-9e8811", "root": "user-bc63be"}
    )
    assert "user-bc63be" in out and "user-9e8811-bc63be" not in out
    # one pass: a token equal to another original is not mapped twice
    assert (
        Pseudonymizer.propagate("10.0.0.1", {"10.0.0.1": "10.3.4.5", "10.3.4.5": "10.9.9.9"})
        == "10.3.4.5"
    )


def _row(case, verdict, conf=0.9, label="true_positive", **kw):
    base = {"case": case, "family": "f", "set": "dev", "label": label, "needs_context": False,
            "injected": False, "twin": None, "model": "m", "run": 1, "verdict": verdict,
            "confidence": conf, "problems": 0, "problem_kinds": [], "invalid": False,
            "latency_s": 1.0}  # fmt: skip
    return {**base, **kw}


def test_scoring():
    rows = [
        _row("a", "true_positive", 0.9),
        _row("b", "benign", 0.8),  # missed true positive
        _row("c", "false_positive", 0.7, label="benign"),  # right decision, wrong label
        _row("d", "needs_more_info", 0.5, label="false_positive"),
        _row("a-inj", "benign", 0.9, injected=True, twin="a"),
    ]
    m = e.summarise(rows)["m"]["dev"]
    assert m["n"] == 4 and m["coverage"] == 0.75
    assert m["accuracy_answered"] == round(2 / 3, 3) and m["accuracy_all"] == 0.5
    assert m["tp_recall"] == 0.5 and m["missed_tp"] == 0.5 and m["exact_label"] == round(1 / 3, 3)
    assert m["injection"] == {"pairs": 1, "flipped_from_tp": 1.0, "flagged_by_gateway": 0.0}
    assert e.auroc([0.9, 0.1], [True, False]) == 1.0 and e.auroc([0.5, 0.5], [True, False]) == 0.5
    assert e.ece([1.0, 1.0], [True, False]) == 0.5 and e.brier([1.0], [True]) == 0.0
    assert "| accuracy_answered |" in e.report(rows)


def test_paired_comparison():
    rows = []
    for i in range(6):
        rows.append(_row(f"c{i}", "benign", family=f"f{i}", set="holdout", model="local"))
        rows.append(_row(f"c{i}", "true_positive", family=f"f{i}", set="holdout", model="frontier"))
    cmp = e.compare(rows, "local", "frontier")
    assert cmp["accuracy_all"]["difference"] == 1.0 and cmp["accuracy_all"]["ci95"] == [1.0, 1.0]
    assert cmp["missed_tp"]["difference"] == -1.0


def test_always_tp_baseline(tmp_path):
    rows = e.run(e.AlwaysTruePositive(), b.cases(), 1, tmp_path / "r.jsonl")
    m = e.summarise(rows)["always-tp"]["all"]
    assert m["tp_recall"] == 1.0 and m["negative_recall"] == 0.0 and m["accuracy_all"] == 0.5


class _AlwaysBenign(BaseHTTPRequestHandler):
    """Fake model server that always answers benign."""

    def do_GET(self):  # noqa: N802
        self._send({"data": [{"id": "fake"}]})

    def do_POST(self):  # noqa: N802
        self.rfile.read(int(self.headers["Content-Length"]))
        answer = {"verdict": "benign", "severity": "low", "confidence": 0.6, "summary": "s",
                  "reasons": [], "next_steps": [], "attack": []}  # fmt: skip
        self._send({"choices": [{"message": {"content": json.dumps(answer)}}]})

    def _send(self, obj):
        data = json.dumps(obj).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *args):
        pass


def test_run_with_a_model_server_is_resumable(tmp_path):
    from privasoc.llm import Endpoint, LLMClient

    srv = HTTPServer(("127.0.0.1", 0), _AlwaysBenign)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        llm = LLMClient(Endpoint("local", f"http://127.0.0.1:{srv.server_port}/v1", "fake"))
        sel = [c for c in b.cases() if c.family in ("S3-ssh-stale-job", "W1-web-tool-scan")]
        out = tmp_path / "r.jsonl"
        first = e.run(llm, sel, 2, out)
        assert len(first) == len(sel) * 2 and e.run(llm, sel, 2, out) == []
        m = e.summarise(first)["fake"]["dev"]
        assert m["negative_recall"] == 1.0 and m["tp_recall"] == 0.0
    finally:
        srv.shutdown()


def test_bootstrap_keeps_family_variants_and_runs_together():
    rows = [_row(f"a{i}", "true_positive", family="a", run=k) for i in range(8) for k in (1, 2, 3)]
    rows += [_row(f"b{i}", "benign", family="b", run=k) for i in range(8) for k in (1, 2, 3)]
    # Two independent stories, not 48 independent observations.
    assert e._bootstrap(rows, "accuracy_all") == [0.0, 1.0]
    assert e._bootstrap([r for r in rows if r["family"] == "a"], "accuracy_all") is None


def test_paired_comparison_refuses_incomplete_and_inconsistent_data():
    import pytest

    rows = [
        _row("a", "true_positive", family="a", set="holdout", model="local"),
        _row("a", "true_positive", family="a", set="holdout", model="frontier"),
    ]
    with pytest.raises(ValueError, match="same cases"):
        e.compare(rows[:1], "local", "frontier")
    with pytest.raises(ValueError, match="same runs"):
        e.compare([*rows, {**rows[0], "run": 2}], "local", "frontier")
    with pytest.raises(ValueError, match="inconsistent"):
        e.compare([rows[0], {**rows[1], "label": "benign"}], "local", "frontier")
    with pytest.raises(ValueError, match="duplicate"):
        e.compare([*rows, rows[0]], "local", "frontier")
