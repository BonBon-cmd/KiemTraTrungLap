"""Quy tắc phân quyền (RBAC + sở hữu). Một nơi duy nhất quyết định "ai xem được gì".

Nguyên tắc: từ chối mặc định. Mọi tài liệu không khớp quy tắc cho phép đều bị chặn.

Hai vai trò:
  admin (Quản trị): xem tất cả bài nộp và kết quả kiểm tra; xem/tải/thêm tài liệu tham chiếu; quản lý tài khoản.
  user (Người dùng): chỉ xem bài và kết quả kiểm tra của chính mình (owner_id).
      KHÔNG truy cập kho tham chiếu (không liệt kê, không tải, không xem trước). Người dùng vẫn thấy đoạn trích
      nguồn trong kết quả của chính mình để biết cần sửa chỗ nào, nhưng tên tệp nguồn được che (xem redact_report).
  Bài cũ không có owner_id: chỉ admin.
  Nguồn Internet tự lưu (role "web"): chỉ admin xem danh sách/xóa. Người dùng thường chỉ thấy trang nào khớp trong
  kết quả của chính mình, kèm tên trang và địa chỉ (vốn là trang công khai), không có mã tài liệu trong kho.
"""
from copy import deepcopy

from sqlalchemy import select, true

from app.models import Document

REDACTED_NAME = "Tài liệu không có quyền xem"


def is_admin(user) -> bool:
    return user.role == "admin"


def may_read_reference(user) -> bool:
    return is_admin(user)


def can_view_document(session, user, document) -> bool:
    if is_admin(user):
        return True
    if document.role in ("reference", "web"):
        return may_read_reference(user)
    return document.owner_id is not None and document.owner_id == user.id


def document_visibility(user):
    """Điều kiện SQL tương đương can_view_document, dùng để lọc danh sách ngay trong truy vấn."""
    if is_admin(user):
        return true()
    return Document.owner_id == user.id


def redact_report(session, user, report: dict) -> dict:
    """Báo cáo lưu nguyên văn đoạn nguồn. Với người dùng thường:
      - nguồn là bài nộp của người khác: ẩn cả nội dung lẫn tên (redacted);
      - nguồn là tài liệu tham chiếu: giữ đoạn trích (để đối chiếu và sửa bài) nhưng che tên tệp và bỏ mã tài liệu,
        nên không có đường dẫn tới kho (masked).
    Quản trị: trả nguyên báo cáo."""
    if is_admin(user):
        return report
    source_ids = {m.get("source_document_id") for m in report.get("matches", [])}
    source_ids |= {s.get("document_id") for s in report.get("sources", [])}
    source_ids.discard(None)
    # Nguồn Internet là trang công khai và đã được ghi nguyên văn trong báo cáo (bản chụp): quyết định hiển thị dựa vào
    # chính báo cáo, không phụ thuộc bản ghi trong CSDL còn hay đã bị quản trị xóa.
    web = {m.get("source_document_id") for m in report.get("matches", []) if m.get("source_kind") == "web"}
    web |= {s.get("document_id") for s in report.get("sources", []) if s.get("kind") == "web"}
    web.discard(None)
    source_ids -= web
    found = {d.id: d for d in session.execute(select(Document).where(Document.id.in_(source_ids))).scalars()} if source_ids else {}
    hidden, masked = set(), []
    for sid in source_ids:
        document = found.get(sid)
        if document is None:
            hidden.add(sid)
        elif document.role == "reference":
            masked.append(sid)
        elif not can_view_document(session, user, document):
            hidden.add(sid)
    result = deepcopy(report)
    # Nhãn che ổn định theo thứ hạng nguồn trong báo cáo: "Nguồn 1", "Nguồn 2"...
    order = [s.get("document_id") for s in result.get("sources", []) if s.get("document_id") in masked]
    order += [sid for sid in masked if sid not in order]
    labels = {sid: f"Nguồn {number}" for number, sid in enumerate(order, 1)}
    for match in result.get("matches", []):
        sid = match.get("source_document_id")
        if sid in hidden:
            match.update(source_text="", source_location={}, source_filename=REDACTED_NAME, redacted=True)
        elif sid in labels:
            match.update(source_filename=labels[sid], source_document_id=None, masked=True)
        elif sid in web:
            match["source_document_id"] = None  # trang công khai: giữ tên và địa chỉ, bỏ mã tài liệu trong kho
    for source in result.get("sources", []):
        sid = source.get("document_id")
        if sid in hidden:
            source.update(filename=REDACTED_NAME, redacted=True)
        elif sid in labels:
            source.update(filename=labels[sid], document_id=None, masked=True)
        elif sid in web:
            source["document_id"] = None
    result.pop("reference_chunk_ids", None)  # mã nội bộ của kho, người dùng thường không cần
    result["redacted_sources"] = len(hidden)
    result["masked_sources"] = len(labels)
    return result
