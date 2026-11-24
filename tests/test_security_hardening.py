# SPDX-License-Identifier: GPL-3.0-or-later
"""Security regression tests for the hardening pass.

Each test names the vulnerability it closes. If one of these fails, the
corresponding hole is open again.
"""

import base64
import io
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from app.db import Database
from app.file_reader import ingest_bytes
from app.main import app, db, session_store
from app.orchestrator import Orchestrator
from app.security import WriteConfirmationManager
from app.sessions import Session


@pytest.fixture
def test_db(tmp_path):
    return Database(tmp_path / "doomed.sqlite")


@pytest.fixture
def client():
    return TestClient(app)


@pytest.fixture
def auth_cookie():
    sess = Session(
        access="tok",
        refresh="ref",
        tenant="tenant_sec",
        name="Sec Student",
        email="sec@school.edu",
        uid="u_sec",
        grade="Grade 11",
    )
    session_store.add(sess)
    return sess.sid


def _pdf_bytes() -> bytes:
    import fitz

    doc = fitz.open()
    page = doc.new_page()
    page.insert_text((50, 72), "Secret content")
    buf = io.BytesIO()
    doc.save(buf)
    return buf.getvalue()


# --- C1: ib:// must not hand out private blobs -------------------------------


def test_ib_ref_cannot_reach_a_private_lms_blob(test_db):
    """`ib://<sha>` must not grant access to a cached private school file."""
    owner_a = "tenant:student_a"
    owner_b = "tenant:student_b"

    res = ingest_bytes(
        db=test_db,
        owner=owner_a,
        raw_bytes=_pdf_bytes(),
        filename="private_homework.pdf",
        source_type="lms",
        ref="lms://resource/10/20",
    )
    sha = res["sha256"]

    # Student B asks for the same blob through the public IB namespace. The
    # call must not succeed by handing back student A's private file.
    from app.file_reader import fetch_and_cache_ref

    try:
        fetched = fetch_and_cache_ref(test_db, owner_b, f"ib://{sha}", session=None)
    except Exception:
        fetched = None

    # Whatever happened, student A's private blob must not now be readable by
    # student B.
    assert fetched is None or fetched.get("sha256") != sha
    assert test_db.can_access_file(owner_b, sha) is False
    with pytest.raises(PermissionError):
        from app.file_reader import get_file_bytes

        get_file_bytes(test_db, owner_b, sha)


def test_ib_ref_requires_a_hex_sha(test_db):
    """A malformed IB ref is rejected before any network call."""
    from app.file_reader import fetch_and_cache_ref

    with pytest.raises(ValueError):
        fetch_and_cache_ref(test_db, "tenant:x", "ib://not-a-sha", session=None)


# --- C2: no unauthenticated access by default -------------------------------


def test_session_requires_auth_by_default(client, monkeypatch):
    monkeypatch.setenv("DOOMED_AUTO_BOOTSTRAP_TOKEN", "0")
    res = client.get("/api/session")
    assert res.status_code == 401


def test_bootstrap_is_off_unless_opted_in(client, monkeypatch, tmp_path):
    """The default must not silently sign a caller in from the local token."""
    monkeypatch.setenv("DOOMED_AUTO_BOOTSTRAP_TOKEN", "0")
    monkeypatch.setattr("app.main.import_local_indus_token", lambda store: None)
    assert client.get("/api/session").status_code == 401


# --- H1: hostile MIME types are never served inline --------------------------


def test_html_upload_is_served_as_an_attachment(client, auth_cookie):
    """An uploaded HTML file must not run as script on our own origin."""
    client.cookies.set("doomed_sid", auth_cookie)

    evil = b"<html><script>window.__pwned=1</script></html>"
    upload = client.post(
        "/api/upload",
        files={"file": ("evil.html", io.BytesIO(evil), "text/html")},
    )
    assert upload.status_code == 200
    sha = upload.json()["sha256"]

    res = client.get(f"/api/files/{sha}")
    assert res.status_code == 200
    assert res.headers["content-type"] == "application/octet-stream"
    assert "attachment" in res.headers["content-disposition"]
    assert res.headers["x-content-type-options"] == "nosniff"
    assert "sandbox" in res.headers["content-security-policy"]


def test_pdf_upload_is_served_inline(client, auth_cookie):
    """A real PDF is still viewable in the in-app viewer."""
    client.cookies.set("doomed_sid", auth_cookie)
    upload = client.post(
        "/api/upload",
        files={"file": ("notes.pdf", io.BytesIO(_pdf_bytes()), "application/pdf")},
    )
    sha = upload.json()["sha256"]
    res = client.get(f"/api/files/{sha}")
    assert res.headers["content-type"] == "application/pdf"
    assert "inline" in res.headers["content-disposition"]


def test_malformed_range_header_does_not_crash(client, auth_cookie):
    client.cookies.set("doomed_sid", auth_cookie)
    upload = client.post(
        "/api/upload",
        files={"file": ("notes.pdf", io.BytesIO(_pdf_bytes()), "application/pdf")},
    )
    sha = upload.json()["sha256"]
    res = client.get(f"/api/files/{sha}", headers={"Range": "bytes=abc"})
    assert res.status_code == 416


# --- H2: visual slug cannot escape the data directory ------------------------


def test_visual_slug_cannot_escape_the_data_dir(tmp_path, monkeypatch):
    """A crafted slug must not write outside `data/viz/<thread>`."""
    import app.orchestrator as orch_mod

    monkeypatch.setattr(orch_mod.config, "ensure_data_dir", lambda: tmp_path)

    db = Database(tmp_path / "doomed.sqlite")
    orch = Orchestrator(db=db, write_mgr=WriteConfirmationManager())
    sess = Session(
        access="t", refresh="r", tenant="tn", name="n", email="e@x.edu", uid="u1"
    )

    png = base64.b64decode(
        "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg=="
    )
    orch._pending_viz["call_x"] = {
        "thread_id": "thread1",
        "owner": sess.owner,
        "kind": "mermaid",
        "slug": "../../../../tmp/pwned",
        "brief": "b",
        "source_code": "graph TD\nA-->B",
        "iteration": 1,
        "maker_messages": [],
    }

    res = orch.handle_viz_feedback(
        sess,
        "call_x",
        {
            "ok": True,
            "dom_warnings": [],
            "png_data_url": "data:image/png;base64," + base64.b64encode(png).decode(),
        },
    )
    assert res["status"] == "published"
    assert not (tmp_path / "tmp" / "pwned").exists()
    assert not Path("/tmp/pwned").exists()
    db.close()


def test_visual_feedback_rejects_a_foreign_owner(tmp_path):
    """Another student cannot publish a visual into someone else's thread."""
    db = Database(tmp_path / "doomed.sqlite")
    orch = Orchestrator(db=db, write_mgr=WriteConfirmationManager())
    owner = Session(access="t", refresh="r", tenant="tn", name="a", email="a@x.edu", uid="u1")
    intruder = Session(access="t2", refresh="r2", tenant="tn", name="b", email="b@x.edu", uid="u2")

    orch._pending_viz["call_y"] = {
        "thread_id": "thread1",
        "owner": owner.owner,
        "kind": "mermaid",
        "slug": "x",
        "brief": "b",
        "source_code": "graph TD\nA-->B",
        "iteration": 1,
        "maker_messages": [],
    }

    res = orch.handle_viz_feedback(intruder, "call_y", {"ok": True, "dom_warnings": []})
    assert res["status"] == "error"
    db.close()


# --- H3: the API key never reaches the browser -------------------------------


def test_settings_never_return_the_api_key(client, auth_cookie):
    client.cookies.set("doomed_sid", auth_cookie)
    res = client.get("/api/settings")
    assert res.status_code == 200
    body = res.text
    assert "api_key\":" not in body
    cfg = res.json()["config"]
    assert "api_key" not in cfg
    assert "api_key_set" in cfg


def test_settings_write_is_loopback_only(client, auth_cookie):
    """A student on another host must not be able to redirect the LLM traffic."""
    client.cookies.set("doomed_sid", auth_cookie)
    res = client.post(
        "/api/settings",
        json={"base_url": "https://attacker.example/v1"},
        headers={"Host": "attacker.example"},
    )
    # TestClient reports host "testclient", so the loopback check must refuse.
    assert res.status_code == 403


# --- M1: a card reply cannot be written into another thread ------------------


def test_card_reply_requires_thread_ownership(tmp_path):
    db = Database(tmp_path / "doomed.sqlite")
    orch = Orchestrator(db=db, write_mgr=WriteConfirmationManager())
    owner = Session(access="t", refresh="r", tenant="tn", name="a", email="a@x.edu", uid="u1")
    intruder = Session(access="t2", refresh="r2", tenant="tn", name="b", email="b@x.edu", uid="u2")

    db.create_thread(owner=owner.owner, title="Private lesson", thread_id="t_priv")

    with pytest.raises(PermissionError):
        orch.submit_card_reply(
            session=intruder,
            thread_id="t_priv",
            card_id="call_q",
            reply_data={"selected": [1]},
        )
    db.close()


# --- M4: file content is marked as untrusted --------------------------------


def test_read_document_marks_content_as_untrusted(test_db):
    from app.file_reader import read_document

    owner = "tenant:x"
    ingest_bytes(
        db=test_db,
        owner=owner,
        raw_bytes=_pdf_bytes(),
        filename="a.pdf",
        source_type="lms",
        ref="lms://resource/1/1",
    )
    doc = read_document(test_db, owner, "lms://resource/1/1", pages="1")
    assert "content_note" in doc
    assert "not addressed to you" in doc["content_note"]


# --- Low: error bodies must not leak internals -------------------------------


def test_acl_error_does_not_name_the_owner(test_db):
    from app.file_reader import get_file_bytes

    owner_a = "tenant:secret_student"
    owner_b = "tenant:attacker"
    ingest_bytes(
        db=test_db,
        owner=owner_a,
        raw_bytes=_pdf_bytes(),
        filename="a.pdf",
        source_type="lms",
        ref="lms://resource/1/1",
    )
    with pytest.raises(PermissionError) as exc:
        get_file_bytes(test_db, owner_b, "a" * 64)
    assert owner_a not in str(exc.value)


# --- S1: unsubmitted/ungraded tests must not bypass lockout -----------------


def test_ungraded_and_not_yet_graded_are_blocked():
    from app.security import assert_not_live_test

    for status in ("ungraded", "not_yet_graded", "under_grading"):
        with pytest.raises(PermissionError):
            assert_not_live_test(item_status=status)


# --- S2: cross-origin redirects must strip authorization headers ------------


def test_safe_fetch_strips_auth_on_cross_origin_redirect():
    from app.security import safe_fetch

    mock_sess = MagicMock()
    mock_sess.get.side_effect = [
        MagicMock(status_code=302, headers={"location": "https://other.domain.com/file.pdf"}),
        MagicMock(status_code=200, headers={"content-type": "application/pdf"}),
    ]

    with patch("app.security.validate_fetch_url"):
        safe_fetch(
            "https://school.domain.com/resource/123",
            headers={"Authorization": "Bearer secret-token", "Accept": "application/pdf"},
            session=mock_sess,
        )

    calls = mock_sess.get.call_args_list
    assert "Authorization" in calls[0].kwargs["headers"]
    assert "Authorization" not in calls[1].kwargs["headers"]


# --- M0.3: Critical Security & Integrity Hardening regressions -------------


def test_local_sessions_have_distinct_owners_and_isolated_data():
    """Two POST /api/session/local calls must produce distinct owners that cannot see each other's threads/files."""
    c1 = TestClient(app)
    c2 = TestClient(app)

    r1 = c1.post("/api/session/local", json={"name": "Student One"})
    r2 = c2.post("/api/session/local", json={"name": "Student Two"})
    assert r1.status_code == 200 and r2.status_code == 200

    sid1 = c1.cookies.get("doomed_sid")
    sid2 = c2.cookies.get("doomed_sid")
    assert sid1 and sid2 and sid1 != sid2
    sess1 = session_store.get(sid1)
    sess2 = session_store.get(sid2)
    assert sess1 is not None and sess2 is not None
    assert sess1.owner != sess2.owner

    # Student 1 creates a thread and uploads a file
    t_res = c1.post("/api/threads", json={"title": "Student 1 Secret Thread"})
    assert t_res.status_code == 200
    t_id = t_res.json()["thread"]["id"]

    up_res = c1.post(
        "/api/upload",
        files={"file": ("secret1.pdf", io.BytesIO(_pdf_bytes()), "application/pdf")},
    )
    assert up_res.status_code == 200
    sha = up_res.json()["sha256"]

    # Student 2 cannot see Student 1's thread or download Student 1's file
    threads2 = c2.get("/api/threads").json()["threads"]
    assert all(t["id"] != t_id for t in threads2)
    assert c2.get(f"/api/threads/{t_id}").status_code == 404
    assert c2.get(f"/api/files/{sha}").status_code == 403


def test_thread_id_validation_and_foreign_thread_no_integrity_leak(tmp_path):
    """Path-traversal thread_ids are rejected; foreign thread_ids never leak sqlite3.IntegrityError."""
    c_owner = TestClient(app)
    c_other = TestClient(app)
    assert c_owner.post("/api/session/local", json={"name": "Owner"}).status_code == 200
    assert c_other.post("/api/session/local", json={"name": "Intruder"}).status_code == 200

    t_res = c_owner.post("/api/threads", json={"title": "Owner Thread"})
    assert t_res.status_code == 200
    foreign_tid = t_res.json()["thread"]["id"]

    # Path traversal rejected on /api/chat/send
    bad_res = c_other.post(
        "/api/chat/send",
        json={"thread_id": "../escape", "message": "hello"},
    )
    assert bad_res.status_code == 400

    # Foreign thread_id rejected cleanly without 500 / IntegrityError
    foreign_res = c_other.post(
        "/api/chat/send",
        json={"thread_id": foreign_tid, "message": "hello"},
    )
    assert foreign_res.status_code == 404

    # Orchestrator directly: handle_viz_feedback rejects ../escape and run_turn raises PermissionError
    local_db = Database(tmp_path / "doomed.sqlite")
    orch = Orchestrator(db=local_db, write_mgr=WriteConfirmationManager())
    s_a = Session(access="t", refresh="r", tenant="tn", name="a", email="a@x.edu", uid="u1")
    s_b = Session(access="t2", refresh="r2", tenant="tn", name="b", email="b@x.edu", uid="u2")
    local_db.create_thread(owner=s_a.owner, title="A thread", thread_id="thread_a_1")

    orch._pending_viz["call_escape"] = {
        "thread_id": "../escape",
        "owner": s_b.owner,
        "kind": "mermaid",
        "slug": "x",
        "brief": "b",
        "source_code": "graph TD\nA-->B",
        "iteration": 1,
        "maker_messages": [],
    }
    viz_res = orch.handle_viz_feedback(s_b, "call_escape", {"ok": True, "dom_warnings": []})
    assert viz_res["status"] == "error"

    with pytest.raises(PermissionError, match="Thread not found"):
        list(orch.process_user_turn(session=s_b, thread_id="thread_a_1", user_message="hi"))
    local_db.close()


def test_http_security_headers_and_csp(client, auth_cookie):
    """Root HTML enforces strict CSP & framing headers; uploaded files keep sandbox CSP."""
    root_res = client.get("/")
    assert root_res.status_code == 200
    assert root_res.headers.get("x-frame-options") == "DENY"
    assert root_res.headers.get("x-content-type-options") == "nosniff"
    assert root_res.headers.get("referrer-policy") == "strict-origin-when-cross-origin"

    csp = root_res.headers.get("content-security-policy", "")
    assert "frame-ancestors 'none'" in csp
    script_src = next(
        (d.strip() for d in csp.split(";") if d.strip().startswith("script-src")),
        "",
    )
    assert script_src and "'unsafe-inline'" not in script_src

    # HTML itself must not carry inline <script> or inline onerror handlers
    html = root_res.text
    assert 'src="/assets/boot.js"' in html
    assert "onerror=" not in html

    # /api/files/{sha256} must preserve its sandbox CSP
    client.cookies.set("doomed_sid", auth_cookie)
    upload = client.post(
        "/api/upload",
        files={"file": ("notes.pdf", io.BytesIO(_pdf_bytes()), "application/pdf")},
    )
    sha = upload.json()["sha256"]
    file_res = client.get(f"/api/files/{sha}")
    assert file_res.status_code == 200
    assert "sandbox" in file_res.headers.get("content-security-policy", "")


def test_oversized_upload_413_and_bounded_fetch_limit(client, auth_cookie, monkeypatch, test_db):
    """Oversized /api/upload returns 413 and bounded fetch rejects > MAX_FILE_BYTES."""
    import app.config as cfg
    from app.file_reader import fetch_and_cache_ref
    from app.security import read_bounded_response

    monkeypatch.setattr(cfg, "MAX_FILE_BYTES", 1024)
    client.cookies.set("doomed_sid", auth_cookie)

    oversized = b"A" * 2048
    res = client.post(
        "/api/upload",
        files={"file": ("big.bin", io.BytesIO(oversized), "application/octet-stream")},
    )
    assert res.status_code == 413

    # Direct read_bounded_response check (streaming chunks without Content-Length)
    stream_resp = MagicMock(headers={})
    stream_resp.iter_content.return_value = [b"B" * 600, b"B" * 600]
    with pytest.raises(ValueError, match="maximum allowed size"):
        read_bounded_response(stream_resp, 1024, truncate=False)

    # fetch_and_cache_ref must reject > MAX_FILE_BYTES from upstream
    big_resp = MagicMock(
        status_code=200,
        headers={"content-type": "application/pdf", "content-length": "2048"},
    )
    big_resp.iter_content.return_value = [b"C" * 2048]
    with patch("app.file_reader.safe_fetch", return_value=big_resp):
        with pytest.raises(ValueError, match="maximum allowed size"):
            fetch_and_cache_ref(test_db, "tenant:u", f"ib://{'a' * 64}", session=None)


def test_ib_endpoints_require_auth(client):
    """Unauthenticated IB proxy routes must return 401."""
    assert client.get("/api/ib/search?q=physics").status_code == 401
    assert client.get("/api/ib/facets?q=physics").status_code == 401


