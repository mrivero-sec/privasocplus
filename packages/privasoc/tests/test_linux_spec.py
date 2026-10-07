"""The Linux review example extracts security fields without classifying opaque bodies."""

import os
import shutil
from pathlib import Path

import pytest

from privasoc import structured
from privasoc.ecs import validate
from privasoc.grounding import ungrounded
from privasoc.sandbox import Sandbox

VECTOR = os.environ.get("PRIVASOC_VECTOR_BIN") or shutil.which("vector")


@pytest.mark.skipif(not VECTOR, reason="Vector unavailable")
def test_linux_review_extraction_and_unclassified_body():
    text = (Path(__file__).parent.parent / "examples/linux-system.yaml").read_text()
    vrl = structured.compile_vrl(structured.load(text))
    bodies = [
        "sshd(pam_unix)[42]: authentication failure; logname= uid=0 rhost=10.0.0.2  user=jdoe",
        "sshd[43]: Failed password for invalid user jdoe from 10.0.0.3 port 4567 ssh2",
        "sshd[43]: Accepted publickey for jdoe from 10.0.0.3 port 4567 ssh2",
        "su(pam_unix)[44]: session opened for user jdoe by (uid=0)",
        "ftpd[45]: ANONYMOUS FTP LOGIN FROM 10.0.0.4,  (anonymous)",
        "kernel: unknown free text says authentication failure",
        "syslogd 1.4.1: restart.",
        " -- root[2421]: ROOT LOGIN ON tty2",
    ]
    lines = ["Jul 27 10:59:53 laptop-01 " + b for b in bodies]
    result = Sandbox(VECTOR).run(vrl, lines + ["unrecognised header"])
    assert not result.compile_error
    assert len(result.outputs) == 8 and result.lines[-1].error
    for line, row in zip(lines, result.lines[: len(lines)], strict=True):
        assert validate(row.output) == []
        assert ungrounded(row.output, line) == []
    pam, failed, accepted, session, ftp, generic, restart, root_login = result.outputs
    assert pam["process"] == {"name": "sshd", "pid": 42}
    assert pam["source"]["ip"] == "10.0.0.2" and pam["user"]["name"] == "jdoe"
    assert pam["event"]["outcome"] == "failure"
    assert failed["source"]["port"] == 4567
    assert accepted["event"]["outcome"] == "success"
    assert session["event"]["type"] == ["start"]
    assert ftp["source"]["ip"] == "10.0.0.4" and ftp["user"]["name"] == "anonymous"
    assert generic["event"] == {"kind": "event"}
    assert "source" not in generic and "user" not in generic
    assert restart["process"]["name"] == "syslogd"
    assert root_login["process"]["pid"] == 2421
