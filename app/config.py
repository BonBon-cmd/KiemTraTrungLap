from dataclasses import dataclass, field
import os
from pathlib import Path

from dotenv import load_dotenv
from sqlalchemy import URL

ROOT = Path(__file__).resolve().parent.parent


@dataclass(frozen=True)
class Settings:
    database_url: str | URL | None = None
    upload_dir: Path = ROOT / "storage" / "uploads"
    max_upload_mb: int = 20
    max_pages: int = 200
    max_chunks: int = 2000
    max_reference_chunks: int = 10000
    chunk_chars: int = 700
    enable_semantic: bool = False
    semantic_model: str = "keepitreal/vietnamese-sbert"
    lexical_threshold: float = 0.30
    semantic_threshold: float = 0.68
    enable_ocr: bool = True
    tesseract_cmd: str = "tesseract"
    ocr_language: str = "vie+eng"
    ocr_dpi: int = 200
    max_ocr_pages: int = 30
    ocr_page_timeout: int = 30
    ocr_min_text_chars: int = 1
    max_alerts_per_source: int = 1000
    max_alerts_per_report: int = 1000
    serper_api_key: str | None = None
    serper_timeout: int = 20
    serper_max_results: int = 10
    serper_max_queries: int = 5
    serper_min_words: int = 8  # số từ tối thiểu trùng nguyên văn (cụm >= 4 từ) giữa đoạn của bài và đoạn trích để coi là nghi vấn
    # Nguồn Internet tự lưu: trang web tìm thấy được tải về, tách đoạn và lưu vào CSDL (role "web") để đối chiếu toàn văn
    # và dùng lại ở các lần kiểm tra sau mà không cần tìm kiếm/tải lại.
    web_auto_save: bool = True
    web_max_pages_per_check: int = 6   # số trang MỚI tối đa được tải trong một lần kiểm tra
    web_max_page_mb: int = 5
    web_fetch_timeout: int = 15
    max_web_chunks: int = 20000        # tổng số đoạn nguồn Internet được giữ trong CSDL; đầy thì không lưu thêm
    # Xác thực/phân quyền. Không có JWT_SECRET: tự sinh khóa ngẫu nhiên mỗi lần chạy
    # (đăng nhập mất hiệu lực khi khởi động lại). Khóa không bao giờ xuất hiện trong repr/log.
    jwt_secret: str | None = field(default=None, repr=False)
    jwt_expire_minutes: int = 60
    cookie_secure: bool = False
    min_password_length: int = 10
    login_max_failures: int = 5
    login_lockout_minutes: int = 15
    # Tự đăng ký chỉ tạo tài khoản vai trò "user" (không bao giờ admin). Tắt (false) nếu chỉ muốn quản trị viên cấp tài khoản.
    allow_registration: bool = True
    register_max_per_hour: int = 30  # mỗi địa chỉ IP; đặt đủ rộng cho một lớp dùng chung mạng

    @classmethod
    def load(cls):
        load_dotenv(ROOT / ".env")
        url = os.getenv("DATABASE_URL") or None
        if not url and os.getenv("PGPASSWORD"):
            url = URL.create(
                "postgresql+psycopg", username=os.getenv("PGUSER", "document_checker"),
                password=os.environ["PGPASSWORD"], host=os.getenv("PGHOST", "127.0.0.1"),
                port=int(os.getenv("PGPORT", "5432")),
                database=os.getenv("PGDATABASE", "document_checker"),
            )
        return cls(
            database_url=url,
            upload_dir=(ROOT / os.getenv("UPLOAD_DIR", "storage/uploads")).resolve(),
            max_upload_mb=max(1, int(os.getenv("MAX_UPLOAD_MB", "20"))),
            max_pages=max(1, int(os.getenv("MAX_PAGES", "200"))),
            max_chunks=max(1, int(os.getenv("MAX_CHUNKS", "2000"))),
            max_reference_chunks=max(1, int(os.getenv("MAX_REFERENCE_CHUNKS", "10000"))),
            chunk_chars=max(100, int(os.getenv("CHUNK_CHARS", "700"))),
            enable_semantic=os.getenv("ENABLE_SEMANTIC", "false").lower() == "true",
            semantic_model=os.getenv("SEMANTIC_MODEL", "keepitreal/vietnamese-sbert"),
            lexical_threshold=float(os.getenv("VERBATIM_THRESHOLD", "0.30")),
            semantic_threshold=float(os.getenv("SEMANTIC_THRESHOLD", "0.68")),
            enable_ocr=os.getenv("ENABLE_OCR", "true").lower() == "true",
            tesseract_cmd=os.getenv("TESSERACT_CMD", "tesseract"),
            ocr_language=os.getenv("OCR_LANGUAGE", "vie+eng"),
            ocr_dpi=min(300, max(100, int(os.getenv("OCR_DPI", "200")))),
            max_ocr_pages=max(1, int(os.getenv("MAX_OCR_PAGES", "30"))),
            ocr_page_timeout=max(5, int(os.getenv("OCR_PAGE_TIMEOUT", "30"))),
            ocr_min_text_chars=max(1, int(os.getenv("OCR_MIN_TEXT_CHARS", "1"))),
            max_alerts_per_source=max(1, min(1000, int(os.getenv("MAX_ALERTS_PER_SOURCE", "1000")))),
            max_alerts_per_report=max(1, min(1000, int(os.getenv("MAX_ALERTS_PER_REPORT", "1000")))),
            serper_api_key=os.getenv("SERPER_API_KEY") or None,
            serper_timeout=max(5, min(60, int(os.getenv("SERPER_TIMEOUT_SECONDS", "20")))),
            serper_max_results=max(1, min(10, int(os.getenv("SERPER_MAX_RESULTS", "10")))),
            serper_max_queries=max(1, min(20, int(os.getenv("SERPER_MAX_QUERIES", "5")))),
            serper_min_words=max(4, int(os.getenv("SERPER_MIN_WORDS", "8"))),
            web_auto_save=os.getenv("WEB_AUTO_SAVE", "true").lower() == "true",
            web_max_pages_per_check=max(1, min(20, int(os.getenv("WEB_MAX_PAGES_PER_CHECK", "6")))),
            web_max_page_mb=max(1, min(30, int(os.getenv("WEB_MAX_PAGE_MB", "5")))),
            web_fetch_timeout=max(3, min(60, int(os.getenv("WEB_FETCH_TIMEOUT_SECONDS", "15")))),
            max_web_chunks=max(1, int(os.getenv("MAX_WEB_CHUNKS", "20000"))),
            jwt_secret=os.getenv("JWT_SECRET") or None,
            jwt_expire_minutes=max(5, min(1440, int(os.getenv("JWT_EXPIRE_MINUTES", "60")))),
            cookie_secure=os.getenv("COOKIE_SECURE", "false").lower() == "true",
            min_password_length=max(8, int(os.getenv("MIN_PASSWORD_LENGTH", "10"))),
            login_max_failures=max(3, int(os.getenv("LOGIN_MAX_FAILURES", "5"))),
            login_lockout_minutes=max(1, int(os.getenv("LOGIN_LOCKOUT_MINUTES", "15"))),
            allow_registration=os.getenv("ALLOW_REGISTRATION", "true").lower() == "true",
            register_max_per_hour=max(1, int(os.getenv("REGISTER_MAX_PER_HOUR", "30"))),
        )
