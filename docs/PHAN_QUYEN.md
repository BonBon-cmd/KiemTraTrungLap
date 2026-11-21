# Xác thực và phân quyền

## Thiết lập lần đầu

```powershell
# 1. Thêm vào .env:  JWT_SECRET=<chuỗi ngẫu nhiên>   (python -c "import secrets; print(secrets.token_urlsafe(48))")
# 2. Tạo bảng users, thêm cột documents.owner_id. Chạy lại an toàn trên CSDL cũ: tài khoản student/lecturer
#    được chuyển thành "user" và bảng assignments (phân công giảng viên) bị xóa vì không còn dùng
.\.venv\Scripts\python.exe -m app.db init
# 3. Tạo quản trị viên đầu tiên (mật khẩu nhập tại chỗ, không đi qua tham số dòng lệnh)
.\.venv\Scripts\python.exe -m app.db create-user --email admin@truong.edu.vn --name "Quản trị" --role admin
```

Tài khoản người dùng do quản trị tạo trong mục **Người dùng** (hoặc `POST /api/users`), hoặc tự đăng ký ở trang chủ
(`POST /api/auth/register`). Tự đăng ký **chỉ tạo vai trò `user`**, giới hạn `REGISTER_MAX_PER_HOUR` lần mỗi giờ cho mỗi IP,
tắt hẳn bằng `ALLOW_REGISTRATION=false`. Người dùng tự đổi mật khẩu ở mục **Tài khoản** (`POST /api/auth/password`);
chưa có đặt lại qua email, quên mật khẩu thì nhờ quản trị đặt lại.

## Hai vai trò và quyền

| Hành động | Người dùng (`user`) | Quản trị (`admin`) |
|---|---|---|
| Nộp bài, chạy kiểm tra | ✅ | ✅ |
| Xem bài, báo cáo, tải/preview file | chỉ bài của mình | tất cả |
| Kho tham chiếu (danh sách, tải, xem trước, số liệu) | ❌ | ✅ |
| Tên tệp nguồn trong kết quả | che thành “Nguồn 1”, “Nguồn 2”… (vẫn thấy đoạn trích) | đầy đủ |
| Thêm tài liệu vào kho tham chiếu | ❌ | ✅ |
| Tìm kiếm web thủ công (`/api/web-search`, tốn hạn mức Serper) | ❌ | ✅ |
| Trang Internet tự lưu khi kiểm tra: thấy tên trang, địa chỉ và đoạn trùng trong kết quả của mình | ✅ | ✅ |
| Danh sách trang Internet đã lưu, xóa trang đã lưu | ❌ | ✅ |
| Quản lý người dùng (tạo, đổi vai trò, khóa, đặt lại mật khẩu) | ❌ | ✅ |

Quản trị đồng thời là người thẩm định nên xem được kết quả của mọi người. Không còn vai trò giảng viên và không còn
bảng phân công. Vai trò lạ còn sót trong dữ liệu cũ (chưa chạy `init`) bị coi là người dùng thường, không bao giờ có quyền quản trị.

Quy tắc nằm ở một nơi: `app/permissions.py` (`can_view_document`, `document_visibility`, `redact_report`).
Mặc định **từ chối**: bài nộp không có `owner_id` (dữ liệu trước khi có phân quyền) chỉ quản trị xem được;
cần gán lại chủ sở hữu bằng SQL nếu muốn trả về cho người dùng.

## Cơ chế

1. `POST /api/auth/login` kiểm tra mật khẩu (bcrypt) → cấp JWT HS256 sống `JWT_EXPIRE_MINUTES` phút,
   đặt trong cookie `HttpOnly; SameSite=Strict` (JS không đọc được, link tải/preview hoạt động).
   API client có thể dùng header `Authorization: Bearer <token>`.
2. Mỗi request: `current_user` giải mã token, nạp người dùng từ CSDL. Vai trò **không** lấy từ token;
   đổi vai trò, khóa tài khoản, đổi mật khẩu tăng `token_version` nên token cũ mất hiệu lực ngay.
3. `require_roles(...)` chặn theo vai trò (403); `can_view_document` chặn theo từng tài liệu.
   Không có quyền xem bài của người khác trả **404** giống hệt "không tồn tại", không lộ ID có thật.
4. `owner_id` luôn lấy từ người đăng nhập, không nhận từ client.

## Phòng thủ khác

- Sai mật khẩu và email không tồn tại cho cùng một thông báo; luôn chạy bcrypt để thời gian phản hồi không lộ email.
- Khóa tạm theo (email, IP) sau `LOGIN_MAX_FAILURES` lần sai trong `LOGIN_LOCKOUT_MINUTES` phút (HTTP 429).
- Token bị từ chối nếu hết hạn, sai khóa, `alg=none`, thiếu `exp`/`sub`/`tv`.
- Không tự hạ quyền/khóa chính mình; luôn còn ít nhất một quản trị đang hoạt động.
- CSRF: cookie `SameSite=Strict` + kiểm tra Origin có sẵn cho POST/PATCH/DELETE.

## Giới hạn hiện tại (cần biết)

- Bộ đếm đăng nhập sai lưu trong bộ nhớ một tiến trình: chạy nhiều worker cần chuyển sang Redis/PostgreSQL.
- Đặt `COOKIE_SECURE=true` và chạy sau HTTPS khi đưa ra ngoài máy cục bộ; middleware chỉ cho phép host `localhost/127.0.0.1`.
- Chưa có đặt lại mật khẩu qua email, đăng nhập 2 bước hay nhật ký truy cập (kiểm toán).
- Kho nguồn hiện chỉ gồm tài liệu tham chiếu; khi cho bài nộp làm nguồn, `redact_report` đã ẩn nguyên văn nguồn người dùng không được xem.

Kiểm thử: `tests/test_auth.py` (47 ca: truy cập chéo giữa hai người dùng, kho tham chiếu chỉ dành cho quản trị,
che tên nguồn, token giả/hết hạn, đăng ký, đổi mật khẩu, khóa đăng nhập, nâng cấp CSDL ba vai trò cũ).
