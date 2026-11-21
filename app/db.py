"""PostgreSQL connection and explicit first-time schema initialization."""
import argparse
import getpass
import sys
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker
from sqlalchemy.engine import make_url

from app.config import Settings
from app.models import Base, ROLES, User
from app.security import PasswordError, hash_password, normalize_email, validate_password


class Database:
    def __init__(self, url):
        if make_url(url).get_backend_name() != "postgresql":
            raise ValueError("Ứng dụng yêu cầu PostgreSQL; không tự chuyển sang SQLite.")
        self.engine = create_engine(
            url, pool_pre_ping=True, pool_size=5, max_overflow=5,
            hide_parameters=True, connect_args={"connect_timeout": 5},
        )
        self.session = sessionmaker(self.engine, expire_on_commit=False)

    def verify(self):
        with self.engine.connect() as connection:
            connection.execute(text("SELECT 1"))
            # Check that schema initialization has actually been performed.
            for table in ("documents", "chunks", "checks", "users"):
                if connection.scalar(text("SELECT to_regclass(:name)"), {"name": table}) is None:
                    raise RuntimeError("Chưa có bảng dữ liệu. Chạy python -m app.db init.")

    def initialize(self):
        Base.metadata.create_all(self.engine)
        # create_all không thêm cột vào bảng đã có: nâng cấp CSDL cũ (trước khi có phân quyền).
        with self.engine.begin() as connection:
            connection.execute(text("ALTER TABLE documents ADD COLUMN IF NOT EXISTS owner_id VARCHAR(36) REFERENCES users(id)"))
            connection.execute(text("CREATE INDEX IF NOT EXISTS ix_documents_owner_id ON documents (owner_id)"))
            # Nguồn Internet tự lưu (role "web"): địa chỉ trang, duy nhất để không lưu trùng.
            connection.execute(text("ALTER TABLE documents ADD COLUMN IF NOT EXISTS source_url VARCHAR(2048)"))
            connection.execute(text("CREATE UNIQUE INDEX IF NOT EXISTS ux_documents_source_url ON documents (source_url)"))
            # Mô hình cũ có 3 vai trò (student/lecturer/admin) và bảng phân công; nay chỉ còn user/admin.
            # Chạy lại nhiều lần vẫn an toàn (không còn hàng nào khớp, bảng đã xóa).
            connection.execute(text("UPDATE users SET role = 'user' WHERE role IN ('student', 'lecturer')"))
            connection.execute(text("DROP TABLE IF EXISTS assignments"))

    def create_user(self, email, full_name, password, role, minimum_password=10):
        email = normalize_email(email)
        validate_password(password, minimum_password, email)
        with self.session() as session:
            user = User(email=email, full_name=full_name.strip(), password_hash=hash_password(password), role=role)
            session.add(user)
            session.commit()
            return user


def main(argv=None):
    parser = argparse.ArgumentParser(prog="python -m app.db")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("init", help="tạo bảng và nâng cấp schema")
    commands.add_parser("check", help="kiểm tra kết nối và schema")
    create = commands.add_parser("create-user", help="tạo tài khoản (dùng để tạo quản trị viên đầu tiên)")
    create.add_argument("--email", required=True)
    create.add_argument("--name", required=True, help="họ tên hiển thị")
    create.add_argument("--role", choices=ROLES, default="admin")
    args = parser.parse_args(argv)
    settings = Settings.load()
    if not settings.database_url:
        print("Chưa cấu hình PostgreSQL. Sao chép .env.example thành .env và nhập thông tin kết nối.")
        return 1
    db = Database(settings.database_url)
    try:
        if args.command == "create-user":
            # Mật khẩu nhập tại chỗ, không nhận qua tham số dòng lệnh (tránh lộ trong lịch sử shell).
            password = getpass.getpass("Mật khẩu: ")
            if password != getpass.getpass("Nhập lại mật khẩu: "):
                print("Hai lần nhập mật khẩu không khớp.")
                return 1
            try:
                user = db.create_user(args.email, args.name, password, args.role, settings.min_password_length)
            except (ValueError, PasswordError) as error:
                print(error)
                return 1
            print(f"Đã tạo tài khoản {user.role}: {user.email}")
            return 0
        if args.command == "init":
            db.initialize()
        db.verify()
        print("PostgreSQL: kết nối thành công; các bảng documents, chunks, checks, users đã sẵn sàng.")
        return 0
    except Exception as error:
        if args.command == "create-user" and "unique" in str(error).lower():
            print("Email này đã được đăng ký.")
            return 1
        print("Không kết nối được hoặc chưa có schema. Kiểm tra dịch vụ PostgreSQL, database, tài khoản và mật khẩu trong .env. Sau đó chạy python -m app.db init.")
        return 1
    finally:
        db.engine.dispose()


if __name__ == "__main__":
    raise SystemExit(main())
