# Đánh giá An toàn & Đề xuất Cải thiện Trước khi Triển khai VPS (Safe Road)

Tài liệu này tổng hợp kết quả đánh giá an toàn, kiểm toán mã nguồn và phân tích khoảng trống vận hành đối với dự án **Safe Road — Anti-Phishing System**, phục vụ công tác tối ưu hóa hệ thống ở môi trường local trước khi chạy thử nghiệm trên máy chủ VPS thực tế.

---

## 1. Phân tích 3 Điểm yếu Bảo mật & Logic Trong Code (Cần Khắc Phục Ngay)

Dưới đây là 3 lỗi logic và bảo mật cụ thể được phát hiện trong quá trình kiểm toán mã nguồn:

### 1.1. [High] Rò rỉ Thông tin Admin Secret ở Mức INFO trong Log Cục bộ
*   **Vị trí mã nguồn:** [cmd/core-api/security.go (dòng 65 & 86)](file:///d:/Go/duan/safe-road/cmd/core-api/security.go#L65-L89)
*   **Chi tiết vấn đề:** Khi chạy ở chế độ cục bộ (local mode) và không cấu hình biến môi trường `SAFE_ROAD_ADMIN_PASSWORD` hoặc `SAFE_ROAD_ADMIN_API_KEY`, hệ thống tự sinh ngẫu nhiên chuỗi bảo mật. Tuy nhiên, mã nguồn lại sử dụng logger có cấu trúc `logjson.Info` để in thẳng mật khẩu và API key dạng plaintext ra log tiêu chuẩn dưới key `"value"`.
*   **Hậu quả:** Toàn bộ mật khẩu admin tối cao sẽ bị rò rỉ vào hệ thống lưu trữ log của container (`docker logs`) hoặc các hệ thống thu thập log tập trung (như Grafana Loki, Elasticsearch). Nếu người vận hành quên cấu hình chế độ sản xuất (`SAFE_ROAD_ENV=production`) trên VPS, các mật khẩu tự sinh cực kỳ nhạy cảm này sẽ phơi bày công khai.
*   **Đề xuất khắc phục:** Chỉ in các thông tin mật khẩu tự sinh này trực tiếp ra console tiêu chuẩn (`os.Stdout`) dạng banner khởi động một lần duy nhất nếu chạy trong terminal tương tác (interactive TTY), không truyền qua logger JSON ghi log có cấu trúc.

---

### 1.2. [Medium] Trùng lặp Metrics khi Xảy ra Sự cố Panic (Double Observe)
*   **Vị trí mã nguồn:** 
    *   [internal/serve/http.go (dòng 71 & 95)](file:///d:/Go/duan/safe-road/internal/serve/http.go#L71-L95)
    *   [cmd/core-api/main.go (dòng 419)](file:///d:/Go/duan/safe-road/cmd/core-api/main.go#L419)
    *   [cmd/dns-resolver/main.go (dòng 505)](file:///d:/Go/duan/safe-road/cmd/dns-resolver/main.go#L505)
*   **Chi tiết vấn đề:** Khi HTTP Handler xảy ra lỗi panic, middleware `Recovery` (nằm trong) sẽ bắt lỗi, ghi nhận cờ `ObservedPanicKey = true` vào request context thông qua lệnh `r = r.WithContext(ctx)` rồi tiến hành quan sát chỉ số lỗi (`obs.Observe`). Tuy nhiên, trong Go, context là bất biến (immutable), việc re-assign `r` chỉ thay đổi con trỏ cục bộ bên trong hàm defer của `Recovery`. 
    Middleware ghi log bên ngoài (`logRequests`) đã gọi `next.ServeHTTP` trước đó và giữ con trỏ request ban đầu, nên không hề nhận được cờ hiệu này (`r.Context().Value(serve.ObservedPanicKey)` luôn trả về `nil`). Do đó, `logRequests` tiếp tục gọi `metrics.Observe` lần thứ hai khi yêu cầu kết thúc với mã lỗi 500.
*   **Hậu quả:** Mỗi sự cố panic của hệ thống HTTP/DoH đều bị đếm trùng lặp **2 lần** trong Telemetry Registry, làm sai lệch báo cáo tỷ lệ lỗi và cảnh báo an toàn.
*   **Đề xuất khắc phục:** Sử dụng một con trỏ tham chiếu kiểu `*bool` được tạo và truyền từ middleware ngoài (`logRequests`) vào context. Middleware trong (`Recovery`) sẽ thay đổi giá trị của con trỏ đó để truyền trạng thái ngược lên phía trên một cách an toàn.

---

### 1.3. [Medium] dns-resolver Không Khởi động Lại khi Lỗi Cấu hình DoT Certificate
*   **Vị trí mã nguồn:** [cmd/dns-resolver/main.go (dòng 149-165)](file:///d:/Go/duan/safe-road/cmd/dns-resolver/main.go#L149-L165)
*   **Chi tiết vấn đề:** Nếu admin cấu hình tệp chứng chỉ DoT (`certFile` và `keyFile`) nhưng quá trình tải tệp gặp lỗi (ví dụ: sai quyền hạn đọc ghi, sai đường dẫn, chứng chỉ hỏng), chương trình chỉ in log `Warn` cảnh báo lỗi, sau đó âm thầm tự sinh chứng chỉ tự ký (self-signed cert) thông qua `generateSelfSignedCert()` và tiếp tục khởi chạy máy chủ DoT trên cổng 853.
*   **Hậu quả:** Tất cả các DNS-over-TLS client trên thực tế (như Private DNS của Android) đòi hỏi chứng chỉ TLS được ký bởi các CA công cộng hợp lệ. Việc âm thầm fallback sang self-signed cert sẽ làm toàn bộ client mất kết nối mạng. Dịch vụ hiển thị trên systemd/Docker vẫn báo trạng thái **UP (Running)** nhưng thực tế hệ thống đã bị tê liệt từ bên ngoài.
*   **Đề xuất khắc phục:** Áp dụng cơ chế **Fail-Fast**. Nếu người vận hành đã chỉ định cấu hình cert/key file mà việc tải tệp thất bại, chương trình phải lập tức in log lỗi nghiêm trọng và dừng chạy (`os.Exit(1)`).

---

## 2. 5 Phần Quan trọng Cần Phát triển & Tối ưu Hóa tại Môi trường Local

Để bảo đảm quá trình chạy thử trên VPS không gặp sự cố về tài nguyên hoặc cấu hình sai, cần tập trung hoàn thiện 5 điểm sau ở local:

1.  **Xây dựng Kịch bản Test Tải Cục bộ (Local Load Testing Tool):**
    *   Sử dụng các công cụ gọn nhẹ như `k6` hoặc `vegeta` để giả lập tải DNS-over-HTTPS (DoH) đạt 500 QPS liên tục qua Caddy Edge.
    *   Mục tiêu: Đánh giá xem hàng đợi ghi telemetry SQLite bất đồng bộ (dung lượng buffer 1000) có bị nghẽn làm tràn bộ nhớ hoặc rò rỉ goroutine khi chạy cường độ cao hay không.
2.  **Cài đặt Tự động Offsite Backup qua `rclone`:**
    *   Tích hợp script tự động đẩy các bản snapshot Redis RDB (`.rdb`) và SQLite (`analysis.db`) kèm tệp `.env` lên Google Drive (15GB free tier) hoặc Backblaze B2.
    *   Mục tiêu: Tránh mất trắng cấu hình whitelist/blacklist thủ công và dữ liệu phân tích khi máy ảo VPS Always Free bị nhà cung cấp thu hồi hoặc lỗi đĩa bất ngờ.
3.  **Hoàn thiện Script Rà quét Cổng Công cộng (Public Edge Security Scan):**
    *   Viết script tự động rà quét cổng (`scripts/check-production-ports.sh`) chạy từ bên ngoài máy ảo.
    *   Mục tiêu: Xác thực chắc chắn chỉ có cổng 80, 443, và 853 mở công khai; các cổng nội bộ như `8080` (Core API), `8081` (DoH Resolver), `6379` (Redis) bị khóa kín để tránh bị các botnet tấn công.
4.  **Tối ưu hóa Trải nghiệm Trang Chặn HTTPS (HTTPS Block Page UX):**
    *   Thiết lập cơ chế trả về mã lỗi DNS thích hợp (như `NXDOMAIN` hoặc `Refused`) thay vì trả về IP trang chặn khi client truy cập web qua HTTPS.
    *   Mục tiêu: Tránh cảnh báo đáng sợ của trình duyệt về lỗi sai lệch chứng chỉ SSL (SSL Certificate Mismatch) khi cố gắng hiển thị trang chặn HTTP trên luồng HTTPS.
5.  **Reconcile và Dọn dẹp Tài liệu Đặc tả (Docs Synchronization):**
    *   Đồng bộ hóa toàn bộ các tài liệu checklist và đặc tả kiến trúc cũ trong thư mục `docs/specs/` để khớp hoàn toàn với cấu trúc code hiện tại.
    *   Mục tiêu: Tránh việc người vận hành đọc nhầm hướng dẫn lỗi thời trong quá trình cấu hình và xử lý sự cố.

---

## 3. Các Hạng mục Khoảng trống Cần Bổ sung Để Lên Production MVP

Hệ thống Safe Road sẽ chính thức đạt trạng thái **Production MVP** khi và chỉ khi hoàn thành đầy đủ các tiêu chí thoát (Exit Criteria) sau:

*   **Network Safety:** Public traffic chỉ được phép đi qua các cổng đã chỉ định (80, 443, 853). Đã chạy thành công port-scan check.
*   **Credential Integrity:** Mật khẩu admin và API key được kiểm tra độ mạnh tự động, nạp từ Docker secrets/file-based secrets (`*_FILE`) và tuyệt đối không rò rỉ trong log.
*   **TLS Production:** DoH và trang quản trị chạy HTTPS thành công với Let's Encrypt qua Caddy. DoT chạy chứng chỉ tin cậy được cập nhật tự động.
*   **Reliable Feeds:** Các nguồn threat intelligence kết nối ổn định thông qua preset `production-free`, có cảnh báo khi dữ liệu feed bị quá hạn (stale feed warning).
*   **Diễn tập Khôi phục (DR Drill):** Đã thực hiện thành công ít nhất một bài kiểm tra khôi phục lại toàn bộ dữ liệu từ bản offsite backup trên máy chủ sạch.
*   **Threat Model:** Đã hoàn thành tài liệu phân tích mô hình hiểm họa theo chuẩn STRIDE để rà soát an ninh hệ thống trước khi vận hành thực tế.
