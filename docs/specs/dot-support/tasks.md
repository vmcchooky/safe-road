# Nhiệm vụ: Hỗ trợ DNS-over-TLS (DoT) (Hướng 7)

## 📋 Giai đoạn 1: Thiết lập cấu hình & Biến môi trường
- [x] Cập nhật cấu hình mặc định trong `dns-resolver`:
  - `SAFE_ROAD_DNS_DOT_ENABLED` (mặc định: `true`)
  - `SAFE_ROAD_DNS_DOT_ADDR` (mặc định: `:853`, khi dev/test dùng `:8533` hoặc `:1853` để tránh cần quyền root).
  - `SAFE_ROAD_DNS_DOT_CERT_FILE` (mặc định: `""`)
  - `SAFE_ROAD_DNS_DOT_KEY_FILE` (mặc định: `""`)
  - `SAFE_ROAD_RATELIMIT_DOH_RPM` (RPM cho DoH, mặc định `100`)
  - `SAFE_ROAD_RATELIMIT_DOT_RPM` (RPM cho DoT, mặc định `100`)
- [x] Cập nhật `.env.example` với các biến môi trường cấu hình DoT mới.
- [x] Cập nhật `docker-compose.yml` để mount các cổng/volume và cấu hình biến môi trường tương ứng.

## 📋 Giai đoạn 2: Cơ chế sinh chứng chỉ TLS & Tích hợp DoT Server
- [x] Viết hàm helper sinh chứng chỉ TLS tự ký tạm thời trên RAM (`generateSelfSignedCert`) trong `cmd/dns-resolver/main.go`.
- [x] Cập nhật struct `app` trong `cmd/dns-resolver/main.go` để tích hợp:
  - `dotLimiter *ratelimit.Limiter`
- [x] Viết hàm `dotHandler(w dns.ResponseWriter, r *dns.Msg)` xử lý giải mã, rate limit, kiểm tra chính sách block/allow, forward tới upstream DoH và trả kết quả về cho client.
- [x] Viết hàm `blockedDNSMessage(query *dns.Msg)` trả về message `dns.Msg` đã được pack sẵn để trả ngược lại cho DoT client khi bị block.
- [x] Viết hàm `sendServfail(w dns.ResponseWriter, r *dns.Msg)` gửi lỗi DNS ServFail an toàn.

## 📋 Giai đoạn 3: Goroutine & Graceful Shutdown
- [x] Cập nhật hàm `main()` trong `cmd/dns-resolver/main.go`:
  - Khởi tạo `dotLimiter` nếu rate limiting được enable.
  - Tải chứng chỉ thực tế hoặc tự động sinh self-signed fallback.
  - Khởi chạy HTTP Server (DoH) và DoT Server song song trên các goroutine.
  - Bắt tín hiệu SIGINT/SIGTERM từ hệ điều hành, thực hiện tắt đồng thời cả hai server bằng `server.Shutdown` và `dotServer.ShutdownContext` một cách an toàn.

## 📋 Giai đoạn 4: Viết Unit Tests & Tích hợp
- [x] Viết các unit tests chuyên sâu cho DoT trong `cmd/dns-resolver/main_test.go`:
  - Kiểm tra tính năng tự sinh chứng chỉ tự ký.
  - Kiểm tra hoạt động cơ bản của DoT handler (Allow/Block).
  - Kiểm tra cơ chế rate limiting cho DoT.
  - Kiểm tra khả năng chạy đa luồng an toàn của DoT handler.
- [x] Chạy kiểm thử toàn diện `go test -race -count=1 ./...` để đảm bảo hệ thống không bị lỗi hồi quy (regression) hay data race.

## 📋 Giai đoạn 5: Xác minh thực tế & Cập nhật tài liệu
- [x] Khởi chạy local server trên cổng tùy biến (ví dụ cổng `:8533` không cần root).
- [x] Sử dụng công cụ truy vấn DNS bảo mật hỗ trợ TLS như `kdig` hoặc `dog` để test DoT:
  ```bash
  kdig @127.0.0.1 -p 8533 +tls example.com
  ```
- [x] Tạo file walkthrough hoàn thành tài liệu.

## 📋 Giai đoạn 6: Rà soát An toàn & Vá lỗ hổng DoT (DoT Security Hardening - MỚI)
- [ ] Vá các lỗ hổng an toàn trong `cmd/dns-resolver/main.go`:
  - [ ] Bổ sung `ReadTimeout` và `WriteTimeout` (5 giây) cho `dotServer` (`dns.Server`).
  - [ ] Bổ sung Panic Recovery (`defer/recover`) ở đầu hàm `dotHandler` để ghi log chi tiết và phản hồi `ServFail` cho client an toàn.
  - [ ] Chuẩn hóa địa chỉ IP client bằng `strings.Trim(clientIP, "[]")` ngay sau bước `net.SplitHostPort` trong `dotHandler`.
  - [ ] Thiết lập context quản lý thời gian sống nghiêm ngặt `context.WithTimeout` (3 giây) khi thực hiện forward sang upstream qua DoH trong `dotHandler`.
- [ ] Cập nhật và chạy bộ kiểm thử (Unit & Concurrency Tests):
  - [ ] Bổ sung ca kiểm thử `TestDoTHandlerPanicRecovery` trong `cmd/dns-resolver/main_test.go`.
  - [ ] Bổ sung ca kiểm thử `TestDoTHandlerIPv6Sanitization` trong `cmd/dns-resolver/main_test.go`.
  - [ ] Chạy toàn bộ test suite `go test -race -v -count=1 ./cmd/dns-resolver/...` xác minh pass 100%.
- [ ] Cập nhật & Đồng bộ tài liệu lưu vết:
  - [ ] Cập nhật báo cáo `walkthrough.md` trong thư mục App Data.
  - [ ] Đồng bộ hóa tài liệu `walkthrough.md` sang `/docs/specs/dot-support/` để lưu giữ tính bày bản của hệ thống.

