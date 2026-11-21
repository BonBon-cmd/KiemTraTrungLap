from datetime import datetime, timezone
from uuid import uuid4

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Integer, JSON, String, Text, UniqueConstraint
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


def identifier():
    return str(uuid4())


def now():
    return datetime.now(timezone.utc)


class Base(DeclarativeBase):
    pass


ROLES = ("user", "admin")


class User(Base):
    __tablename__ = "users"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=identifier)
    email: Mapped[str] = mapped_column(String(254), unique=True, index=True)  # luôn lưu chữ thường
    full_name: Mapped[str] = mapped_column(String(120))
    password_hash: Mapped[str] = mapped_column(String(100))  # bcrypt, không bao giờ trả ra API
    role: Mapped[str] = mapped_column(String(16), index=True)  # user | admin
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    # Tăng khi đổi mật khẩu/vai trò/khóa tài khoản: mọi token đã cấp trước đó mất hiệu lực.
    token_version: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class Document(Base):
    __tablename__ = "documents"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=identifier)
    filename: Mapped[str] = mapped_column(String(255))
    file_type: Mapped[str] = mapped_column(String(8))
    role: Mapped[str] = mapped_column(String(16), index=True)  # submission | reference | web
    sha256: Mapped[str] = mapped_column(String(64), index=True)
    # NULL for submissions; a reference can only be imported once by content hash.
    reference_hash: Mapped[str | None] = mapped_column(String(64), unique=True)
    stored_name: Mapped[str] = mapped_column(String(50))  # "" với nguồn Internet: văn bản nằm trong bảng chunks
    # Chỉ có ở role "web": địa chỉ đã chuẩn hóa của trang được lưu (duy nhất, dùng để không tải/lưu trùng).
    source_url: Mapped[str | None] = mapped_column(String(2048), unique=True)
    # Người tải lên. NULL = dữ liệu cũ trước khi có phân quyền: chỉ quản trị xem được bài nộp loại này.
    owner_id: Mapped[str | None] = mapped_column(ForeignKey("users.id"), index=True)
    size_bytes: Mapped[int] = mapped_column(Integer)
    warnings: Mapped[list] = mapped_column(JSON, default=list)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    chunks: Mapped[list["Chunk"]] = relationship(cascade="all, delete-orphan", order_by="Chunk.ordinal")


class Chunk(Base):
    __tablename__ = "chunks"
    __table_args__ = (UniqueConstraint("document_id", "ordinal"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=identifier)
    document_id: Mapped[str] = mapped_column(ForeignKey("documents.id"), index=True)
    ordinal: Mapped[int] = mapped_column(Integer)
    text: Mapped[str] = mapped_column(Text)
    location: Mapped[dict] = mapped_column(JSON)


class Check(Base):
    __tablename__ = "checks"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=identifier)
    document_id: Mapped[str] = mapped_column(ForeignKey("documents.id"), index=True)
    engine: Mapped[str] = mapped_column(String(20))
    threshold: Mapped[float] = mapped_column(Float)
    coverage: Mapped[float] = mapped_column(Float)
    # Immutable report snapshot: matched text/locations survive later corpus changes.
    report: Mapped[dict] = mapped_column(JSON)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
