"""Dependency xác thực/vai trò và các route đăng nhập, đăng ký, đổi mật khẩu, quản lý người dùng."""
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError

from app.models import User
from app.security import (
    COOKIE_NAME, PasswordError, create_access_token, decode_access_token, hash_password,
    normalize_email, validate_password, verify_password,
)

Role = Literal["user", "admin"]
LOGIN_ERROR = "Email hoặc mật khẩu không đúng."


def public_user(user: User) -> dict:
    return {"id": user.id, "email": user.email, "full_name": user.full_name, "role": user.role,
            "is_active": user.is_active, "created_at": user.created_at.isoformat() if user.created_at else None}


def _database(request: Request):
    database = request.app.state.database
    if database is None:
        raise HTTPException(503, "Chưa cấu hình PostgreSQL. Điền .env theo .env.example rồi khởi động lại web.")
    return database


def _token_from(request: Request) -> str | None:
    header = request.headers.get("authorization", "")
    if header[:7].lower() == "bearer ":
        return header[7:].strip() or None
    return request.cookies.get(COOKIE_NAME)


def current_user(request: Request) -> User:
    """Xác thực mỗi request: đọc token, nạp người dùng từ CSDL (vai trò/khóa tài khoản có hiệu lực ngay)."""
    database = _database(request)
    unauthorized = HTTPException(401, "Cần đăng nhập.", headers={"WWW-Authenticate": "Bearer"})
    token = _token_from(request)
    claims = decode_access_token(request.app.state.jwt_secret, token) if token else None
    if not claims:
        raise unauthorized
    with database.session() as session:
        user = session.get(User, claims["sub"])
    if user is None or not user.is_active or user.token_version != claims["tv"]:
        raise unauthorized
    return user


def require_roles(*roles: str):
    def dependency(user: User = Depends(current_user)) -> User:
        if user.role not in roles:
            raise HTTPException(403, "Bạn không có quyền thực hiện thao tác này.")
        return user
    return dependency


class LoginBody(BaseModel):
    email: str = Field(max_length=254)
    password: str = Field(max_length=200)


class PasswordBody(BaseModel):
    current_password: str = Field(max_length=200)
    new_password: str = Field(max_length=200)


class RegisterBody(BaseModel):
    email: str = Field(max_length=254)
    full_name: str = Field(min_length=1, max_length=120)
    password: str = Field(max_length=200)


class NewUserBody(BaseModel):
    email: str = Field(max_length=254)
    full_name: str = Field(min_length=1, max_length=120)
    password: str = Field(max_length=200)
    role: Role


class UserPatchBody(BaseModel):
    full_name: str | None = Field(default=None, min_length=1, max_length=120)
    role: Role | None = None
    is_active: bool | None = None
    password: str | None = Field(default=None, max_length=200)


def build_router() -> APIRouter:
    router = APIRouter()
    admin_only = require_roles("admin")

    def set_cookie(request, response, user):
        settings = request.app.state.settings
        token = create_access_token(request.app.state.jwt_secret, user, settings.jwt_expire_minutes)
        response.set_cookie(
            COOKIE_NAME, token, max_age=settings.jwt_expire_minutes * 60, httponly=True,
            samesite="strict", secure=settings.cookie_secure, path="/",
        )
        return token

    # ------------------------------------------------------------------ đăng nhập
    @router.post("/api/auth/login")
    def login(body: LoginBody, request: Request, response: Response):
        settings, limiter = request.app.state.settings, request.app.state.login_limiter
        try:
            email = normalize_email(body.email)
        except ValueError:
            email = body.email.strip().lower()[:254]
        key = (email, request.client.host if request.client else "?")
        wait = limiter.retry_after(key)
        if wait:
            raise HTTPException(429, f"Đăng nhập sai quá nhiều lần. Thử lại sau {wait} giây.", headers={"Retry-After": str(wait)})
        with _database(request).session() as session:
            user = session.scalar(select(User).where(User.email == email))
        # Luôn chạy bcrypt (kể cả khi không có tài khoản) để không lộ email nào tồn tại.
        valid = verify_password(body.password, user.password_hash if user else None)
        if not (valid and user and user.is_active):
            limiter.record_failure(key)
            raise HTTPException(401, LOGIN_ERROR)
        limiter.reset(key)
        token = set_cookie(request, response, user)
        return {"access_token": token, "token_type": "bearer", "user": public_user(user)}

    @router.post("/api/auth/register", status_code=201)
    def register(body: RegisterBody, request: Request, response: Response):
        """Tự đăng ký: luôn là SINH VIÊN (vai trò không nhận từ client). Chưa xác minh email vì hệ thống chưa gửi thư."""
        settings, limiter = request.app.state.settings, request.app.state.register_limiter
        if not settings.allow_registration:
            raise HTTPException(403, "Hệ thống đang tắt tự đăng ký. Hãy nhờ quản trị viên tạo tài khoản.")
        key = ("register", request.client.host if request.client else "?")
        wait = limiter.retry_after(key)
        if wait:
            raise HTTPException(429, f"Đăng ký quá nhiều lần từ địa chỉ này. Thử lại sau {wait} giây.", headers={"Retry-After": str(wait)})
        limiter.record_failure(key)  # mọi lần thử đều được tính, kể cả thành công
        full_name = " ".join(body.full_name.split())
        if not full_name:
            raise HTTPException(422, "Vui lòng nhập họ tên.")
        try:
            email = normalize_email(body.email)
            validate_password(body.password, settings.min_password_length, email)
        except (ValueError, PasswordError) as error:
            raise HTTPException(422, str(error)) from error
        with _database(request).session() as session:
            user = User(email=email, full_name=full_name, password_hash=hash_password(body.password), role="user")
            session.add(user)
            try:
                session.commit()
            except IntegrityError as error:
                raise HTTPException(409, "Email này đã được đăng ký.") from error
            token = set_cookie(request, response, user)
            return {"access_token": token, "token_type": "bearer", "user": public_user(user)}

    @router.post("/api/auth/logout")
    def logout(response: Response):
        response.delete_cookie(COOKIE_NAME, path="/")
        return {"detail": "Đã đăng xuất."}

    @router.get("/api/auth/me")
    def me(user: User = Depends(current_user)):
        return public_user(user)

    @router.post("/api/auth/password")
    def change_password(body: PasswordBody, request: Request, response: Response, user: User = Depends(current_user)):
        settings, limiter = request.app.state.settings, request.app.state.password_limiter
        key = ("password", user.id)
        wait = limiter.retry_after(key)  # chống đoán mật khẩu hiện tại bằng phiên đăng nhập bị chiếm
        if wait:
            raise HTTPException(429, f"Nhập sai mật khẩu hiện tại quá nhiều lần. Thử lại sau {wait} giây.", headers={"Retry-After": str(wait)})
        if not verify_password(body.current_password, user.password_hash):
            limiter.record_failure(key)
            raise HTTPException(403, "Mật khẩu hiện tại không đúng.")
        limiter.reset(key)
        if body.new_password == body.current_password:
            raise HTTPException(422, "Mật khẩu mới phải khác mật khẩu hiện tại.")
        try:
            validate_password(body.new_password, settings.min_password_length, user.email)
        except PasswordError as error:
            raise HTTPException(422, str(error)) from error
        with request.app.state.database.session() as session:
            row = session.get(User, user.id)
            row.password_hash = hash_password(body.new_password)
            row.token_version += 1  # đăng xuất mọi phiên cũ
            session.commit()
            set_cookie(request, response, row)
        return {"detail": "Đã đổi mật khẩu. Các phiên đăng nhập khác đã bị đăng xuất."}

    # ------------------------------------------------------------------ quản lý người dùng (admin)
    @router.get("/api/users")
    def list_users(request: Request, role: Role | None = None, _: User = Depends(admin_only)):
        with _database(request).session() as session:
            statement = select(User).order_by(User.created_at.desc()).limit(500)
            if role:
                statement = statement.where(User.role == role)
            return [public_user(user) for user in session.scalars(statement)]

    @router.post("/api/users", status_code=201)
    def create_user(body: NewUserBody, request: Request, _: User = Depends(admin_only)):
        settings = request.app.state.settings
        try:
            email = normalize_email(body.email)
            validate_password(body.password, settings.min_password_length, email)
        except (ValueError, PasswordError) as error:
            raise HTTPException(422, str(error)) from error
        with _database(request).session() as session:
            user = User(email=email, full_name=body.full_name.strip(), password_hash=hash_password(body.password), role=body.role)
            session.add(user)
            try:
                session.commit()
            except IntegrityError as error:
                raise HTTPException(409, "Email này đã được đăng ký.") from error
            return public_user(user)

    @router.patch("/api/users/{user_id}")
    def update_user(user_id: str, body: UserPatchBody, request: Request, admin: User = Depends(admin_only)):
        settings = request.app.state.settings
        with _database(request).session() as session:
            user = session.get(User, user_id)
            if user is None:
                raise HTTPException(404, "Không tìm thấy người dùng.")
            losing_admin = user.role == "admin" and ((body.role and body.role != "admin") or body.is_active is False)
            if losing_admin:
                if user.id == admin.id:
                    raise HTTPException(409, "Không thể tự hạ quyền hoặc khóa chính tài khoản quản trị đang dùng.")
                remaining = session.scalar(select(func.count(User.id)).where(User.role == "admin", User.is_active, User.id != user.id))
                if not remaining:
                    raise HTTPException(409, "Phải còn ít nhất một quản trị viên đang hoạt động.")
            revoke = False
            if body.full_name is not None:
                user.full_name = body.full_name.strip()
            if body.role is not None and body.role != user.role:
                user.role, revoke = body.role, True
            if body.is_active is not None and body.is_active != user.is_active:
                user.is_active, revoke = body.is_active, True
            if body.password is not None:
                try:
                    validate_password(body.password, settings.min_password_length, user.email)
                except PasswordError as error:
                    raise HTTPException(422, str(error)) from error
                user.password_hash, revoke = hash_password(body.password), True
            if revoke:
                user.token_version += 1
            session.commit()
            return public_user(user)

    return router
