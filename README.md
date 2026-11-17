# PPV VPN — Per-App Split-Tunneling WireGuard & WARP+ cho Windows

Ứng dụng desktop trên Windows giúp dùng **WireGuard / Cloudflare WARP+** theo **từng ứng dụng cụ thể** (Per-App Split Tunneling) thay vì đẩy toàn bộ lưu lượng máy qua VPN như APKCombo VPN.

## Tính năng chính
- **Simple Firewall & Chia tách ứng dụng (Per-App Firewall + Split Tunneling)**:
  - Hiển thị trực tiếp danh sách các tiến trình đang chạy và ứng dụng đã lưu quy tắc dạng bảng giống **simplewall** (hỗ trợ tìm kiếm `Ctrl+F`, lọc theo trạng thái, chuột phải mở menu nhanh, tô màu theo hành động).
  - Gán quyền mạng trực tiếp cho từng ứng dụng / tiến trình:
    - **Qua VPN (`wg-out`)** *(xanh dương)*: đi qua đường hầm WireGuard / WARP+.
    - **Cho phép mạng (`Allow`)** *(xanh lá)*: cho phép kết nối trực tiếp, không qua VPN.
    - **Chặn mạng (`Block`)** *(đỏ)*: chặn hoàn toàn kết nối mạng bằng **Windows Firewall (WFP)** (kể cả khi tắt VPN) kết hợp `reject` trong `sing-box`.
  - Hỗ trợ **2 chế độ Firewall**: mặc định **Allowlist chặt (giống simplewall)** (chặn app chưa gán trong tunnel VPN và/hoặc ở tầng Windows Firewall, chỉ mở các app đã chọn + tự giữ DNS/DHCP & `sing-box.exe`) và **Blacklist (An toàn)** (mặc định mở, chỉ chặn app chọn Block); tự khôi phục cấu hình gốc khi tắt Firewall.
  - Chế độ **Include** / **Exclude** và khớp theo **tên `.exe`** hoặc **đường dẫn chính xác**.
- **Quản lý Profile WireGuard & WARP+**:
  - Tự động nhận diện `warpplus.conf` có sẵn trong thư mục ứng dụng (xem mẫu [warpplus.conf.example](warpplus.conf.example)).
  - Hỗ trợ nhập nhiều file `.conf` hoặc dán cấu hình WireGuard.
  - Nút **Tạo Cloudflare WARP miễn phí** trực tiếp trong app.
- **Tự động dọn VPN xung đột & tự tải core `sing-box`**:
  - Khi bấm **Kết nối**, app tự tắt các VPN/dịch vụ khác đang chạy (APKCombo VPN, WireGuard, Cloudflare WARP...) để tránh xung đột định tuyến.
  - Nếu chưa có `bin/sing-box.exe`, ứng dụng sẽ tự động tải bản `sing-box` v1.14.4 chính thức từ GitHub và kiểm tra SHA-256.
- **Giám sát kết nối & Nhật ký trực tiếp**:
  - Xem từng tiến trình đang kết nối qua `VPN (wg-out)` hay `Trực tiếp (direct)` cùng tốc độ tải lên / tải xuống thời gian thực.
- **Khay hệ thống (System Tray)**: biểu tượng đổi màu theo trạng thái (xám: chưa kết nối, vàng: đang kết nối, xanh lá: đã kết nối, đỏ: lỗi) và tự xin quyền Administrator (UAC) khi tạo TUN (`sing-box` + Wintun).

## Cách chạy từ mã nguồn
```powershell
python -m venv .venv
.\.venv\Scripts\pip install PySide6 cryptography requests pywin32
.\.venv\Scripts\python.exe -m ppv
```
Hoặc chạy nhanh bằng `launch.ps1`. Ở lần chạy đầu, app sẽ tự tải `bin/sing-box.exe` về nếu chưa có.

## Đóng gói thành file `.exe`
```powershell
.\.venv\Scripts\python.exe build_exe.py
```
Kết quả nằm tại `dist\PPV-VPN\PPV-VPN.exe` (tự tải `bin\sing-box.exe` nếu chưa có trước khi đóng gói).

## Lưu ý khi dùng song song với APKCombo VPN
Nếu bạn đang bật tunnel toàn hệ thống của APKCombo VPN (`WireGuardTunnel$warpplus`), hãy tắt trước khi bật PPV VPN để tránh xung đột định tuyến trên Windows.
