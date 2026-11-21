"""Kiểm thử xác thực và phân quyền: vai trò, cô lập dữ liệu giữa người dùng, token, khóa đăng nhập."""
from datetime import datetime, timedelta, timezone

import jwt
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select, text

from app.config import Settings
from app.main import create_app
from app.models import Check, Document, User
from app.permissions import REDACTED_NAME, redact_report
from app.security import LoginLimiter, create_access_token, hash_password, verify_password
from conftest import ADMIN_EMAIL, PASSWORD, login, make_docx, make_user
from test_web import OTHER, TEXT, upload


def submit(client, content=None, name="baocao.docx"):
    response = upload(client, "/api/checks", content, name)
    assert response.status_code == 201, response.text
    return response.json()


def add_reference(admin, content=None, name="nguon.docx"):
    response = upload(admin, "/api/references", content, name)
    assert response.status_code == 201, response.text
    return response.json()


# ----------------------------------------------------------------------------- chưa đăng nhập

PROTECTED = [
    ("get", "/api/auth/me"), ("get", "/api/stats"), ("get", "/api/documents"), ("get", "/api/checks"),
    ("get", "/api/checks/abc"), ("get", "/api/documents/abc/file"), ("get", "/api/documents/abc/preview"),
    ("get", "/api/users"), ("post", "/api/users"), ("patch", "/api/users/abc"),
    ("post", "/api/references"), ("post", "/api/checks"), ("post", "/api/web-search"),
    ("post", "/api/auth/password"),
]


@pytest.mark.parametrize("method,path", PROTECTED)
def test_every_protected_endpoint_requires_login(web, method, path):
    _, app, _ = web
    anonymous = TestClient(app)
    response = getattr(anonymous, method)(path)
    assert response.status_code == 401, f"{method} {path} -> {response.status_code}"
    assert response.headers["www-authenticate"] == "Bearer"


def test_public_endpoints_stay_public(web):
    _, app, _ = web
    anonymous = TestClient(app)
    assert anonymous.get("/").status_code == 200
    assert anonymous.get("/api/health").status_code == 200
    assert anonymous.post("/api/auth/logout").status_code == 200


# ----------------------------------------------------------------------------- đăng nhập

def test_login_sets_httponly_strict_cookie_and_returns_no_secrets(web):
    _, app, _ = web
    client = TestClient(app)
    response = login(client)
    cookie = response.headers["set-cookie"].lower()
    assert "httponly" in cookie and "samesite=strict" in cookie
    body = response.json()
    assert body["user"]["email"] == ADMIN_EMAIL and body["user"]["role"] == "admin"
    assert "password" not in str(body).lower() and "$2b$" not in str(body)
    assert client.get("/api/auth/me").json()["email"] == ADMIN_EMAIL
    assert client.post("/api/auth/logout").status_code == 200
    assert client.get("/api/auth/me").status_code == 401


def test_bearer_header_works_without_cookie(web):
    _, app, _ = web
    token = login(TestClient(app)).json()["access_token"]
    api_client = TestClient(app)
    assert api_client.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"}).status_code == 200


def test_login_errors_are_identical_for_unknown_email_wrong_password_and_inactive(web):
    admin, app, _ = web
    created = admin.post("/api/users", json={"email": "off@example.com", "full_name": "Off", "password": PASSWORD, "role": "user"}).json()
    admin.patch(f"/api/users/{created['id']}", json={"is_active": False})
    client = TestClient(app)
    bodies = []
    for email, password in [("nobody@example.com", PASSWORD), (ADMIN_EMAIL, "sai-mat-khau-123"), ("off@example.com", PASSWORD)]:
        response = client.post("/api/auth/login", json={"email": email, "password": password})
        assert response.status_code == 401
        bodies.append(response.json())
    assert bodies[0] == bodies[1] == bodies[2]


def test_login_lockout_after_repeated_failures(web):
    _, app, settings = web
    client = TestClient(app)
    for _ in range(settings.login_max_failures):
        assert client.post("/api/auth/login", json={"email": ADMIN_EMAIL, "password": "sai-mat-khau-123"}).status_code == 401
    locked = client.post("/api/auth/login", json={"email": ADMIN_EMAIL, "password": PASSWORD})
    assert locked.status_code == 429 and int(locked.headers["retry-after"]) > 0  # kể cả mật khẩu đúng
    make_user(app.state.database, "other@example.com", "user")
    assert client.post("/api/auth/login", json={"email": "other@example.com", "password": PASSWORD}).status_code == 200


def test_limiter_window_expires():
    limiter = LoginLimiter(max_failures=2, window_seconds=0.05)
    key = ("a@example.com", "1.1.1.1")
    limiter.record_failure(key); limiter.record_failure(key)
    assert limiter.retry_after(key) > 0
    import time; time.sleep(0.08)
    assert limiter.retry_after(key) == 0


def test_cross_origin_login_rejected(web):
    _, app, _ = web
    response = TestClient(app).post("/api/auth/login", json={"email": ADMIN_EMAIL, "password": PASSWORD}, headers={"Origin": "https://evil.example"})
    assert response.status_code == 403


def test_password_hashing():
    hashed = hash_password(PASSWORD)
    assert hashed != PASSWORD and hashed.startswith("$2")
    assert verify_password(PASSWORD, hashed)
    assert not verify_password("khac", hashed)
    assert not verify_password("a" * 100, hashed)  # quá 72 byte bị từ chối, không cắt âm thầm
    assert not verify_password(PASSWORD, None)


# ----------------------------------------------------------------------------- token

def test_forged_expired_and_wrong_algorithm_tokens_are_rejected(web):
    _, app, settings = web
    database = app.state.database
    with database.session() as session:
        admin = session.scalar(select(User).where(User.email == ADMIN_EMAIL))
    client = TestClient(app)

    def status(token):
        return client.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"}).status_code

    assert status(create_access_token(settings.jwt_secret, admin, 5)) == 200
    assert status(create_access_token(settings.jwt_secret, admin, -1)) == 401          # hết hạn
    assert status(create_access_token("khoa-sai-" + "y" * 40, admin, 5)) == 401         # ký bằng khóa khác
    claims = {"sub": admin.id, "tv": admin.token_version, "exp": datetime.now(timezone.utc) + timedelta(minutes=5)}
    assert status(jwt.encode(claims, key=None, algorithm="none")) == 401                # alg=none
    assert status(jwt.encode({"sub": admin.id, "tv": 0}, settings.jwt_secret, algorithm="HS256")) == 401  # thiếu exp
    assert status("khong.phai.token") == 401
    good = create_access_token(settings.jwt_secret, admin, 5)
    assert status(good[:-3] + ("AAA" if not good.endswith("AAA") else "BBB")) == 401    # sửa chữ ký


def test_token_for_deleted_or_changed_account_is_revoked(people):
    clients, users, app, _ = people
    admin = clients["admin"]
    assert clients["a"].get("/api/auth/me").status_code == 200
    admin.patch(f"/api/users/{users['a'].id}", json={"role": "admin"})          # đổi vai trò
    assert clients["a"].get("/api/auth/me").status_code == 401
    assert clients["b"].get("/api/auth/me").status_code == 200
    admin.patch(f"/api/users/{users['b'].id}", json={"is_active": False})       # khóa tài khoản
    assert clients["b"].get("/api/auth/me").status_code == 401


def test_change_password_revokes_other_sessions(web):
    _, app, _ = web
    first, second = TestClient(app), TestClient(app)
    login(first); login(second)
    new_password = "Mat-khau-moi-2-ok"
    assert first.post("/api/auth/password", json={"current_password": "sai-mat-khau-1", "new_password": new_password}).status_code == 403
    assert first.post("/api/auth/password", json={"current_password": PASSWORD, "new_password": "123"}).status_code == 422
    assert first.post("/api/auth/password", json={"current_password": PASSWORD, "new_password": new_password}).status_code == 200
    assert first.get("/api/auth/me").status_code == 200      # phiên hiện tại được cấp token mới
    assert second.get("/api/auth/me").status_code == 401     # phiên khác bị đăng xuất
    assert TestClient(app).post("/api/auth/login", json={"email": ADMIN_EMAIL, "password": PASSWORD}).status_code == 401
    assert TestClient(app).post("/api/auth/login", json={"email": ADMIN_EMAIL, "password": new_password}).status_code == 200


def test_change_password_rejects_same_password_and_limits_guessing(web):
    _, app, _ = web
    client = TestClient(app); login(client)
    same = client.post("/api/auth/password", json={"current_password": PASSWORD, "new_password": PASSWORD})
    assert same.status_code == 422 and "khác" in same.json()["detail"]
    for _ in range(5):
        assert client.post("/api/auth/password", json={"current_password": "sai-mat-khau-1", "new_password": "Mat-khau-moi-2-ok"}).status_code == 403
    blocked = client.post("/api/auth/password", json={"current_password": PASSWORD, "new_password": "Mat-khau-moi-2-ok"})
    assert blocked.status_code == 429 and int(blocked.headers["retry-after"]) > 0   # đúng mật khẩu cũng bị chặn trong thời gian khóa


# ----------------------------------------------------------------------------- tự đăng ký

REGISTER = {"email": "Sinh.Vien@Example.com", "full_name": "  Nguyễn   Văn  An ", "password": "Mat-khau-dang-ky-1"}


def test_register_creates_ordinary_user_only_and_logs_in(web):
    _, app, _ = web
    anonymous = TestClient(app)
    response = anonymous.post("/api/auth/register", json={**REGISTER, "role": "admin", "is_active": True})  # trường lạ bị bỏ qua
    assert response.status_code == 201, response.text
    user = response.json()["user"]
    assert user["role"] == "user" and user["email"] == "sinh.vien@example.com" and user["full_name"] == "Nguyễn Văn An"
    assert "password" not in str(response.json()) and "hash" not in str(response.json())
    assert anonymous.get("/api/auth/me").json()["role"] == "user"        # đã đăng nhập sẵn
    assert anonymous.get("/api/users").status_code == 403
    assert TestClient(app).post("/api/auth/login", json={"email": "sinh.vien@example.com", "password": REGISTER["password"]}).status_code == 200


def test_register_validation_and_duplicates(web):
    _, app, _ = web
    client = TestClient(app)
    assert client.post("/api/auth/register", json={**REGISTER, "password": "123"}).status_code == 422
    assert client.post("/api/auth/register", json={**REGISTER, "email": "khong-phai-email"}).status_code == 422
    assert client.post("/api/auth/register", json={**REGISTER, "full_name": "   "}).status_code == 422
    assert client.post("/api/auth/register", json={**REGISTER, "password": "sinh.vien@example.com"}).status_code == 422
    assert client.post("/api/auth/register", json=REGISTER).status_code == 201
    assert TestClient(app).post("/api/auth/register", json=REGISTER).status_code == 409
    assert TestClient(app).post("/api/auth/register", json={**REGISTER, "email": ADMIN_EMAIL}).status_code == 409   # không chiếm email quản trị


def test_register_can_be_disabled_and_is_rate_limited(tmp_path, postgres_db):
    off = create_app(Settings(upload_dir=tmp_path / "u", jwt_secret="test-secret-" + "x" * 40, allow_registration=False), postgres_db)
    with TestClient(off) as client:
        assert client.get("/api/health").json()["registration_enabled"] is False
        assert client.post("/api/auth/register", json=REGISTER).status_code == 403
    limited = create_app(Settings(upload_dir=tmp_path / "u", jwt_secret="test-secret-" + "x" * 40, register_max_per_hour=3), postgres_db)
    with TestClient(limited) as client:
        assert client.get("/api/health").json()["registration_enabled"] is True
        codes = [client.post("/api/auth/register", json={**REGISTER, "email": f"u{i}@example.com"}).status_code for i in range(4)]
        assert codes == [201, 201, 201, 429]


# ----------------------------------------------------------------------------- vai trò (RBAC)

def test_only_admin_manages_references_and_users(people):
    clients, users, _, _ = people
    client = clients["a"]
    assert upload(client, "/api/references").status_code == 403
    assert client.get("/api/users").status_code == 403
    assert client.post("/api/users", json={"email": "n@example.com", "full_name": "N", "password": PASSWORD, "role": "admin"}).status_code == 403
    assert client.patch(f"/api/users/{users['a'].id}", json={"role": "admin"}).status_code == 403
    assert upload(clients["admin"], "/api/references").status_code == 201


def test_user_cannot_escalate_via_patch_on_self(people):
    clients, users, _, _ = people
    assert clients["a"].patch(f"/api/users/{users['a'].id}", json={"role": "admin"}).status_code == 403
    assert clients["a"].get("/api/auth/me").json()["role"] == "user"


def test_web_search_is_admin_only(people):
    clients, _, _, _ = people
    assert clients["a"].post("/api/web-search", json={"query": "x"}).status_code == 403
    assert clients["admin"].post("/api/web-search", json={"query": "x"}).status_code == 503  # được phép, nhưng chưa cấu hình Serper


def test_only_two_roles_exist_and_old_ones_are_rejected(people):
    clients, _, _, _ = people
    admin = clients["admin"]
    base = {"email": "r@example.com", "full_name": "R", "password": PASSWORD}
    for role in ("student", "lecturer", "superuser"):
        assert admin.post("/api/users", json={**base, "role": role}).status_code == 422, role
    assert admin.post("/api/users", json={**base, "role": "user"}).status_code == 201
    assert admin.get("/api/assignments").status_code == 404   # cơ chế phân công giảng viên đã bỏ


# ----------------------------------------------------------------------------- cô lập dữ liệu

def test_user_sees_only_own_submissions_and_cannot_guess_ids(people):
    clients, users, app, _ = people
    add_reference(clients["admin"])
    report_a = submit(clients["a"])
    report_b = submit(clients["b"], make_docx(OTHER), "b.docx")
    doc_a, doc_b = report_a["document_id"], report_b["document_id"]

    # B không đụng được vào dữ liệu của A, ở mọi endpoint; luôn 404 để không lộ sự tồn tại.
    unknown = clients["b"].get("/api/checks/khong-ton-tai")
    for path in (f"/api/checks/{report_a['id']}", f"/api/documents/{doc_a}/file", f"/api/documents/{doc_a}/preview"):
        response = clients["b"].get(path)
        assert response.status_code == 404, path
    # Phản hồi "bị cấm" giống hệt "không tồn tại": không lộ ID có thật.
    assert clients["b"].get(f"/api/checks/{report_a['id']}").json() == unknown.json()
    assert clients["b"].get(f"/api/documents/{doc_a}/file").json()["detail"] == "Không tìm thấy tài liệu."

    # Danh sách và thống kê chỉ gồm bài của chính mình.
    assert [c["id"] for c in clients["b"].get("/api/checks").json()] == [report_b["id"]]
    assert {d["id"] for d in clients["b"].get("/api/documents?role=submission").json()} == {doc_b}
    assert clients["b"].get("/api/stats").json()["checks"] == 1
    assert clients["a"].get("/api/stats").json()["checks"] == 1

    # Chủ sở hữu xem được; quản trị xem được tất cả.
    assert clients["a"].get(f"/api/checks/{report_a['id']}").status_code == 200
    assert clients["a"].get(f"/api/documents/{doc_a}/file").status_code == 200
    assert clients["admin"].get(f"/api/checks/{report_a['id']}").status_code == 200
    assert {c["id"] for c in clients["admin"].get("/api/checks").json()} == {report_a["id"], report_b["id"]}
    assert clients["admin"].get("/api/stats").json()["checks"] == 2


def test_owner_comes_from_token_not_from_client(people):
    clients, users, app, _ = people
    add_reference(clients["admin"])
    # Cố gửi owner_id giả trong form: tham số lạ bị bỏ qua.
    response = clients["a"].post("/api/checks", files={"file": ("a.docx", make_docx(TEXT))},
                                 data={"engine": "lexical", "owner_id": users["b"].id})
    assert response.status_code == 201
    with app.state.database.session() as session:
        document = session.get(Document, response.json()["document_id"])
        assert document.owner_id == users["a"].id


def test_reference_corpus_is_readable_by_admin(people):
    clients, _, _, _ = people
    reference = add_reference(clients["admin"])
    admin = clients["admin"]
    assert [d["id"] for d in admin.get("/api/documents?role=reference").json()] == [reference["id"]]
    assert admin.get(f"/api/documents/{reference['id']}/file").status_code == 200
    assert admin.get(f"/api/documents/{reference['id']}/preview").status_code in (200, 503)
    assert admin.get("/api/stats").json()["references"] == 1


def test_user_cannot_reach_reference_corpus_in_any_way(people):
    clients, _, _, _ = people
    reference = add_reference(clients["admin"])
    student = clients["a"]  # người dùng thường
    assert student.get("/api/documents?role=reference").status_code == 403
    assert student.get("/api/documents").json() == []                         # không lẫn tài liệu kho vào danh sách chung
    assert student.get(f"/api/documents/{reference['id']}/file").status_code == 404      # 404, không lộ là có tồn tại
    assert student.get(f"/api/documents/{reference['id']}/preview").status_code == 404
    stats = student.get("/api/stats").json()
    assert "references" not in stats and "reference_chunks" not in stats and stats["checks"] == 0
    assert upload(student, "/api/references").status_code == 403


def test_user_report_keeps_passages_but_hides_source_names_and_ids(people):
    clients, _, _, _ = people
    add_reference(clients["admin"], name="Bao_cao_khoa_truoc_2025.docx")
    report = submit(clients["a"])
    assert report["matches"], "cần có cảnh báo để kiểm tra việc che tên"
    stored = clients["a"].get(f"/api/checks/{report['id']}").json()
    assert "Bao_cao_khoa_truoc_2025" not in str(stored)
    assert "reference_chunk_ids" not in stored
    for match in stored["matches"]:
        assert match["source_filename"].startswith("Nguồn ") and match["source_document_id"] is None
        assert match["source_text"], "đoạn trích vẫn cần để người dùng biết chỗ phải sửa"
    assert all(s["document_id"] is None for s in stored["sources"])
    # Quản trị vẫn thấy tên thật.
    admin_view = clients["admin"].get(f"/api/checks/{report['id']}").json()
    assert admin_view["matches"][0]["source_filename"] == "Bao_cao_khoa_truoc_2025.docx"


def test_submission_without_owner_is_admin_only(people):
    clients, _, app, _ = people
    add_reference(clients["admin"])
    report = submit(clients["a"])
    with app.state.database.session() as session:
        session.get(Document, report["document_id"]).owner_id = None   # dữ liệu cũ trước khi có phân quyền
        session.commit()
    assert clients["a"].get(f"/api/checks/{report['id']}").status_code == 404
    assert clients["a"].get("/api/checks").json() == []
    assert clients["admin"].get(f"/api/checks/{report['id']}").status_code == 200


def test_report_redacts_sources_the_viewer_may_not_read(people):
    """Nếu bài nộp của người khác được dùng làm nguồn, nguyên văn đoạn đó không được lộ cho người không có quyền."""
    clients, users, app, _ = people
    add_reference(clients["admin"])
    report_a = submit(clients["a"])
    report_b = submit(clients["b"], make_docx(OTHER), "b.docx")
    reference_id = next(d["id"] for d in clients["admin"].get("/api/documents?role=reference").json())
    fake = {
        "matches": [
            {"source_document_id": report_a["document_id"], "source_text": "NGUYEN VAN CUA A", "source_filename": "a.docx", "source_location": {"page": 1}},
            {"source_document_id": reference_id, "source_text": "tai lieu tham chieu", "source_filename": "nguon.docx", "source_location": {"page": 2}},
        ],
        "sources": [{"document_id": report_a["document_id"], "filename": "a.docx"}, {"document_id": reference_id, "filename": "nguon.docx"}],
    }
    with app.state.database.session() as session:
        viewer_b = session.get(User, users["b"].id)
        redacted = redact_report(session, viewer_b, fake)
        assert redacted["matches"][0]["source_text"] == "" and redacted["matches"][0]["redacted"] is True
        assert redacted["matches"][0]["source_filename"] == REDACTED_NAME
        assert "NGUYEN VAN CUA A" not in str(redacted)
        assert redacted["matches"][1]["source_text"] == "tai lieu tham chieu"   # đoạn trích nguồn tham chiếu vẫn thấy...
        assert redacted["matches"][1]["source_filename"] == "Nguồn 1" and redacted["matches"][1]["source_document_id"] is None  # ...nhưng che tên và mã (người dùng thường)
        assert fake["matches"][0]["source_text"] == "NGUYEN VAN CUA A"          # không sửa dữ liệu gốc
        # Chủ bài thấy nguyên văn bài của mình; nguồn tham chiếu vẫn bị che tên với người dùng thường. Quản trị thấy đủ.
        owner_view = redact_report(session, session.get(User, users["a"].id), fake)
        assert owner_view["matches"][0]["source_text"] == "NGUYEN VAN CUA A" and owner_view["matches"][0]["source_filename"] == "a.docx"
        assert owner_view["matches"][1]["source_filename"] == "Nguồn 1"
        assert redact_report(session, session.get(User, users["admin"].id), fake) is fake


# ----------------------------------------------------------------------------- quản lý người dùng

def test_user_management_rules(people):
    clients, users, _, _ = people
    admin = clients["admin"]
    valid = {"email": "New.User@Example.com", "full_name": "  Nguyễn Văn A  ", "password": PASSWORD, "role": "user"}
    created = admin.post("/api/users", json=valid)
    assert created.status_code == 201
    assert created.json()["email"] == "new.user@example.com" and created.json()["full_name"] == "Nguyễn Văn A"
    assert "password" not in created.text.lower()
    assert admin.post("/api/users", json={**valid, "email": "NEW.user@example.com"}).status_code == 409
    assert admin.post("/api/users", json={**valid, "email": "khac@example.com", "password": "short"}).status_code == 422
    assert admin.post("/api/users", json={**valid, "email": "khac@example.com", "password": "1234567890"}).status_code == 422
    assert admin.post("/api/users", json={**valid, "email": "khac@example.com", "password": "a" * 80}).status_code == 422
    assert admin.post("/api/users", json={**valid, "email": "khong-hop-le"}).status_code == 422
    assert admin.post("/api/users", json={**valid, "email": "k@example.com", "role": "superuser"}).status_code == 422
    for user in admin.get("/api/users").json():
        assert set(user) == {"id", "email", "full_name", "role", "is_active", "created_at"}
    assert admin.patch("/api/users/khong-ton-tai", json={"is_active": False}).status_code == 404


def test_admin_cannot_lock_themselves_or_remove_last_admin(people):
    clients, users, _, _ = people
    admin = clients["admin"]
    me = users["admin"].id
    assert admin.patch(f"/api/users/{me}", json={"role": "user"}).status_code == 409
    assert admin.patch(f"/api/users/{me}", json={"is_active": False}).status_code == 409
    second = admin.post("/api/users", json={"email": "admin2@example.com", "full_name": "Admin 2", "password": PASSWORD, "role": "admin"}).json()
    second_client = TestClient(clients["admin"].app)
    login(second_client, "admin2@example.com")
    assert admin.patch(f"/api/users/{second['id']}", json={"is_active": False}).status_code == 200  # còn admin khác
    assert second_client.get("/api/auth/me").status_code == 401
    assert admin.patch(f"/api/users/{me}", json={"is_active": False}).status_code == 409           # vẫn không tự khóa


# ----------------------------------------------------------------------------- CSDL / công cụ

def test_initialize_upgrades_database_created_before_authorization(postgres_db):
    with postgres_db.engine.begin() as connection:
        connection.execute(text("ALTER TABLE documents DROP COLUMN owner_id"))
        assert connection.scalar(text("SELECT count(*) FROM information_schema.columns WHERE table_name='documents' AND column_name='owner_id' AND table_schema=current_schema()")) == 0
    postgres_db.initialize()
    postgres_db.initialize()  # chạy lại được (idempotent)
    with postgres_db.engine.begin() as connection:
        assert connection.scalar(text("SELECT count(*) FROM information_schema.columns WHERE table_name='documents' AND column_name='owner_id' AND table_schema=current_schema()")) == 1
    postgres_db.verify()


def test_initialize_migrates_old_three_role_data(postgres_db):
    """CSDL cũ có student/lecturer và bảng assignments: init chuyển hết thành user và bỏ bảng phân công."""
    make_user(postgres_db, "sv@example.com", "user")
    make_user(postgres_db, "gv@example.com", "user")
    make_user(postgres_db, "qt@example.com", "admin")
    with postgres_db.engine.begin() as connection:
        connection.execute(text("UPDATE users SET role='student' WHERE email='sv@example.com'"))
        connection.execute(text("UPDATE users SET role='lecturer' WHERE email='gv@example.com'"))
        connection.execute(text("CREATE TABLE IF NOT EXISTS assignments (id VARCHAR(36) PRIMARY KEY, lecturer_id VARCHAR(36), student_id VARCHAR(36))"))
    postgres_db.initialize()
    postgres_db.initialize()  # chạy lại vẫn an toàn
    with postgres_db.engine.begin() as connection:
        roles = dict(connection.execute(text("SELECT email, role FROM users WHERE email IN ('sv@example.com','gv@example.com','qt@example.com')")).all())
        assert roles == {"sv@example.com": "user", "gv@example.com": "user", "qt@example.com": "admin"}
        assert connection.scalar(text("SELECT to_regclass('assignments')")) is None
    postgres_db.verify()


def test_account_with_legacy_role_is_treated_as_ordinary_user(web):
    """Quên chạy init sau khi nâng cấp: vai trò lạ không bao giờ có quyền quản trị (từ chối mặc định)."""
    admin, app, _ = web
    database = app.state.database
    make_user(database, "cu@example.com", "user")
    with database.engine.begin() as connection:
        connection.execute(text("UPDATE users SET role='lecturer' WHERE email='cu@example.com'"))
    legacy = TestClient(app)
    login(legacy, "cu@example.com")
    assert legacy.get("/api/documents?role=reference").status_code == 403
    assert legacy.get("/api/users").status_code == 403
    assert upload(legacy, "/api/references").status_code == 403


def test_create_user_cli_does_not_take_password_from_arguments(postgres_db, monkeypatch, capsys):
    import app.db as dbmodule
    answers = iter([PASSWORD, PASSWORD])
    monkeypatch.setattr(dbmodule.getpass, "getpass", lambda prompt="": next(answers))
    monkeypatch.setattr(dbmodule.Settings, "load", classmethod(lambda cls: Settings(database_url="postgresql://unused")))
    monkeypatch.setattr(dbmodule, "Database", lambda url: postgres_db)
    assert dbmodule.main(["create-user", "--email", "Gv@Example.com", "--name", "Người dùng", "--role", "user"]) == 0
    with postgres_db.session() as session:
        user = session.scalar(select(User).where(User.email == "gv@example.com"))
        assert user.role == "user" and verify_password(PASSWORD, user.password_hash)
    answers = iter([PASSWORD, "khac"])
    assert dbmodule.main(["create-user", "--email", "gv2@example.com", "--name", "X", "--role", "user"]) == 1
    with pytest.raises(SystemExit):   # vai trò cũ không còn hợp lệ
        dbmodule.main(["create-user", "--email", "gv3@example.com", "--name", "Y", "--role", "lecturer"])


def test_secret_not_leaked_in_settings_repr():
    assert "super-secret-value" not in repr(Settings(jwt_secret="super-secret-value"))


def test_fresh_check_response_is_already_masked_for_user(people):
    """Lỗi từng gặp: bản trả về ngay sau khi nộp bài chưa che tên tệp kho; chỉ bản mở lại từ lịch sử mới được che."""
    clients, _, _, _ = people
    reference = add_reference(clients["admin"])
    fresh = clients["a"].post("/api/checks", files={"file": ("a.docx", make_docx(TEXT))}, data={"engine": "lexical"})
    assert fresh.status_code == 201
    report = fresh.json()
    text = fresh.text
    assert reference["id"] not in text and "nguon.docx" not in text and "reference_chunk_ids" not in report
    assert report["matches"] and all(m["source_filename"].startswith("Nguồn ") and m["source_document_id"] is None for m in report["matches"])
    assert report["masked_sources"] >= 1
    # Quản trị nhận bản đầy đủ, và bản lưu trong CSDL không bị che
    full = clients["admin"].post("/api/checks", files={"file": ("b.docx", make_docx(TEXT))}, data={"engine": "lexical"}).json()
    assert full["matches"][0]["source_document_id"] == reference["id"]
    assert clients["admin"].get(f'/api/checks/{report["id"]}').json()["matches"][0]["source_document_id"] == reference["id"]
