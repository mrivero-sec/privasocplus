"""privasoc+ P0: closing an alert records when and why (ground truth of step 8)."""

import sqlite3

import pytest

from privasoc.detect import alerts as al
from privasoc.store import Store


def _alert(store):
    al.raise_alert(store, kind="sigma", rule_id="r1", title="t", level="high",
                   source="syslog:192.0.2.1", at="2026-10-07T10:00:00+00:00", event_ids=[])  # fmt: skip
    return al.alerts(store, "open")[0]["id"]


def test_close_records_time_and_reason(tmp_path):
    store = Store(tmp_path / "p.db")
    aid = _alert(store)
    assert al.alert(store, aid)["closed_at"] is None
    al.set_status(store, aid, "closed_fp", "benign")
    a = al.alert(store, aid)
    assert a["status"] == "closed_fp" and a["close_reason"] == "benign" and a["closed_at"]
    al.set_status(store, aid, "acknowledged")  # reopened: no longer closed
    a = al.alert(store, aid)
    assert a["closed_at"] is None and a["close_reason"] is None
    al.set_status(store, aid, "closed_tp")
    assert al.alert(store, aid)["close_reason"] == "true_positive"  # default reason


@pytest.mark.parametrize(
    ("status", "reason"),
    [("closed_tp", "benign"), ("closed_fp", "true_positive"), ("acknowledged", "benign")],
)
def test_inconsistent_reason_is_refused(tmp_path, status, reason):
    store = Store(tmp_path / "p.db")
    aid = _alert(store)
    with pytest.raises(ValueError):
        al.set_status(store, aid, status, reason)


def test_old_database_is_migrated(tmp_path):
    path = tmp_path / "old.db"
    conn = sqlite3.connect(path)
    conn.execute(
        "CREATE TABLE alerts (id INTEGER PRIMARY KEY, kind TEXT NOT NULL, rule_id TEXT NOT NULL,"
        " title TEXT NOT NULL, level TEXT NOT NULL, source TEXT NOT NULL,"
        " group_key TEXT NOT NULL DEFAULT '', first_seen TEXT NOT NULL, last_seen TEXT NOT NULL,"
        " count INTEGER NOT NULL DEFAULT 0, status TEXT NOT NULL DEFAULT 'new',"
        " created_at TEXT NOT NULL, updated_at TEXT NOT NULL, detail TEXT, triage TEXT,"
        " notified INTEGER NOT NULL DEFAULT 0)"
    )
    conn.commit()
    conn.close()
    store = Store(path)
    cols = {r[1] for r in store.conn.execute("PRAGMA table_info(alerts)")}
    assert {"closed_at", "close_reason"} <= cols
