# jwt-debugger

[English](README.md) | [Tiếng Việt](README.vi.md)

[![CI](https://github.com/haiphamngoc-dev/jwt-debugger/actions/workflows/ci.yml/badge.svg)](https://github.com/haiphamngoc-dev/jwt-debugger/actions)
[![Crates.io](https://img.shields.io/crates/v/jwt-debugger.svg)](https://crates.io/crates/jwt-debugger)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Rust: 1.80+](https://img.shields.io/badge/Rust-1.80%2B-orange.svg)](https://www.rust-lang.org)

Công cụ CLI và thư viện Rust bảo mật theo mặc định (secure-by-default), tốc độ cao dùng để kiểm tra, giải mã, xác thực và gỡ lỗi **JSON Web Tokens (JWT / JWS / JWK / JWKS)**.

Được thiết kế cho các lập trình viên, kỹ sư bảo mật, DevOps và tự động hóa trong các pipeline CI/CD.

---

## Tính Năng Nổi Bật

- **Bảo Mật Theo Mặc Định (Secure by Default)**:
  - Bắt buộc xác thực chữ ký mật mã học trước khi tin cậy bất kỳ claim nào.
  - Ngăn chặn tấn công Algorithm Confusion (ví dụ: không cho phép dùng public key của RSA để verify token HMAC).
  - Tự động từ chối token không chữ ký (`alg: none`) trừ khi được bật tường minh qua `--allow-unsecured`.
  - Bắt buộc giao thức HTTPS đối với các endpoint Remote JWKS (có thể bật cờ cho môi trường local development).
- **Hỗ Trợ Đầy Đủ Các Thuật Toán Tiêu Chuẩn**:
  - **HMAC**: `HS256`, `HS384`, `HS512`
  - **RSA PKCS#1 v1.5**: `RS256`, `RS384`, `RS512`
  - **RSA-PSS**: `PS256`, `PS384`, `PS512`
  - **ECDSA**: `ES256` (P-256), `ES384` (P-384)
  - **EdDSA**: `EdDSA` (Ed25519)
  - **Unsecured**: `none`
- **Kiểm Tra Chuyên Sâu & Cảnh Báo An Toàn (Linting)**:
  - Phân tích cấu trúc phân đoạn và kích thước byte.
  - Tính toán thời gian: tuổi token (age), tổng thời gian tồn tại (lifetime), và thời gian còn lại trước khi hết hạn.
  - Tự động phát hiện lỗi bảo mật: thiếu `exp`, thời điểm `iat`/`nbf` trong tương lai, `typ` bất thường, vòng đời token quá dài.
- **Nguồn Khóa Xác Thực Đa Dạng**:
  - Chuỗi secret trực tiếp, file secret, mã hóa Hex, Base64, hoặc Base64URL.
  - Khóa công khai PEM (PKCS#8 SPKI, PKCS#1 RSA, SEC1 EC, Ed25519).
  - File JSON Web Key (`JWK`) và Key Set (`JWKS`) cục bộ.
  - Endpoint Remote JWKS qua HTTPS với cơ chế tự động khớp Key ID (`kid`).
- **Tối Ưu Hóa Cho Scripting & Pipeline UNIX**:
  - Mã thoát tiến trình (semantic exit codes `0`-`7`) hỗ trợ tự động hóa trong CI/CD.
  - Hỗ trợ định dạng JSON (`--json`), rút gọn (`--compact`), và chế độ yên lặng (`--quiet`).
  - Đọc token từ positional argument, cờ `--token`, file `--token-file`, hoặc đường ống `stdin`.
- **Tự Động Hoàn Thành Lệnh (Shell Autocompletions)**:
  - Trình sinh completion gốc cho Bash, Zsh, Fish, PowerShell, Elvish.

---

## Kiến Trúc Quy Trình Xác Thực

```mermaid
flowchart TD
    A["Đầu vào JWT Thô\n(CLI arg, flag, file, stdin)"] --> B["Phân Tích & Kiểm Tra Cấu Trúc\n(3 phân đoạn Base64URL)"]
    B --> C{"Lệnh Thực Thi"}

    C -->|"decode"| D["Giải Mã Header JOSE, Payload & Chữ Ký"]
    C -->|"inspect"| E["Phân Tích Thời Gian & Cảnh Báo An Toàn\n(Age, Lifetime, Security Warnings)"]
    C -->|"verify"| F["Tìm Khóa Xác Thực\n(Secret, PEM, JWK, Remote JWKS)"]

    F --> G{"Khớp Thuật Toán & Kiểm Tra Tương Thích"}
    G -->|Không khớp| H["Từ chối (Chống Algorithm Confusion)"]
    G -->|Tương thích| I["Kiểm Tra Chữ Ký Mật Mã Học"]

    I -->|Hợp lệ| J["Xác Thực Các Claim Tiêu Chuẩn\n(exp, nbf, iat, iss, aud, sub + leeway)"]
    I -->|Không hợp lệ| K["Mã thoát 4: EXIT_SIGNATURE_INVALID"]

    J -->|Thành công| L["Mã thoát 0: VERIFICATION SUCCESSFUL"]
    J -->|Thất bại| M["Mã thoát 5: EXIT_CLAIMS_INVALID"]
```

---

## Cài Đặt

### Cài đặt từ Crates.io (Khuyên dùng)

```bash
cargo install jwt-debugger
```

### Build từ mã nguồn

```bash
git clone https://github.com/haiphamngoc-dev/jwt-debugger.git
cd jwt-debugger
cargo build --release
cp target/release/jwt-debugger /usr/local/bin/
```

---

## Hướng Dẫn Sử Dụng CLI

```text
Usage: jwt-debugger [OPTIONS] <COMMAND>

Commands:
  decode      Giải mã và hiển thị header, payload, và chữ ký JWT
  inspect     Kiểm tra cấu trúc, metadata, claims chuẩn, thời gian, và cảnh báo bảo mật
  verify      Xác thực chữ ký JWT và kiểm tra ràng buộc claims
  claims      Hiển thị và đánh giá các claims JWT cùng phân tích thời gian
  header      Chỉ trích xuất và hiển thị header JWT
  payload     Chỉ trích xuất và hiển thị payload JWT
  signature   Trích xuất và hiển thị chữ ký JWT dưới nhiều định dạng mã hóa
  jwk         Kiểm tra và xác thực token bằng JSON Web Keys (JWK / JWKS)
  completion  Sinh script shell autocompletion
  help        Hiển thị trợ giúp
```

---

### 1. Giải Mã Token (`decode`)

Giải mã toàn bộ các phân đoạn của token:

```bash
jwt-debugger decode "$TOKEN"
```

Đầu ra mẫu trên terminal:

```text
Header
──────
{
  "alg": "HS256",
  "typ": "JWT"
}

Payload
───────
{
  "sub": "1234567890",
  "name": "John Doe",
  "iat": 1516239022
}

Signature
─────────
Algorithm:      HS256
Base64URL:      SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c
Bytes:          32
```

Xuất định dạng JSON cho máy đọc:

```bash
jwt-debugger decode "$TOKEN" --json
```

---

### 2. Kiểm Tra Chuyên Sâu & Cảnh Báo Bảo Mật (`inspect`)

Phân tích cấu trúc token, tính toán thời gian và quét các lỗ hổng bảo mật tiềm ẩn:

```bash
jwt-debugger inspect "$TOKEN" --timezone UTC
```

Đầu ra mẫu trên terminal:

```text
JWT Debugger - Inspect

Structure
─────────
Segments:       3
Format:         JWS Compact Serialization
Size:           172 bytes (header: 27, payload: 57, signature: 32)

Header
──────
Algorithm:      HS256
Type:           JWT

Claims
──────
Subject:        1234567890
Issued At:      2018-01-18 01:30:22 UTC
Expires At:     2026-09-18 15:30:00 UTC

Lifetime
────────
Token lifetime: 8y 243d
Age:            8y 243d
Expires in:     2h 15m

Signature
─────────
Algorithm:      HS256
Signature bytes: 32
Verification:   NOT PERFORMED

Warnings
────────
- LONG_LIFETIME: Token lifetime is unusually long (8y 243d).
```

---

### 3. Xác Thực Token (`verify`)

#### Khóa Bí Mật HMAC (HS256, HS384, HS512)

```bash
# Qua chuỗi secret trực tiếp
jwt-debugger verify "$TOKEN" --alg HS256 --secret "your-256-bit-secret"

# Qua file secret (khuyên dùng để tránh lộ secret trong danh sách tiến trình)
jwt-debugger verify "$TOKEN" --alg HS256 --secret-file ./secret.key

# Qua mã hóa Hex, Base64, hoặc Base64URL
jwt-debugger verify "$TOKEN" --alg HS256 --secret-hex "796f75722d736563726574"
jwt-debugger verify "$TOKEN" --alg HS256 --secret-base64 "eW91ci1zZWNyZXQ="
```

#### Khóa Công Khai PEM RSA, ECDSA, và EdDSA

```bash
# RSA (RS256 / PS256) với file PEM public key
jwt-debugger verify "$TOKEN" --alg RS256 --public-key ./public_key.pem

# ECDSA (ES256 / ES384) với file PEM public key
jwt-debugger verify "$TOKEN" --alg ES256 --public-key ./ec_public.pem

# EdDSA (Ed25519) với file PEM public key
jwt-debugger verify "$TOKEN" --alg EdDSA --public-key ./ed25519_public.pem
```

#### Remote JWKS (Auth0, Okta, Keycloak, Firebase...)

```bash
# Tự động chọn đúng key dựa vào trường 'kid' trong header của token
jwt-debugger verify "$TOKEN" \
  --alg RS256 \
  --jwks-url https://auth.example.com/.well-known/jwks.json \
  --issuer https://auth.example.com/ \
  --audience my-api-audience
```

#### Ràng Buộc Claims & Độ Lệch Thời Gian (Leeway)

```bash
jwt-debugger verify "$TOKEN" \
  --alg HS256 \
  --secret-file ./secret.key \
  --issuer https://issuer.example.com \
  --audience my-service \
  --subject user123 \
  --leeway 30s \
  --require-exp \
  --require-iat
```

---

### 4. Trích Xuất Phân Đoạn Riêng Lẻ

Trích xuất trực tiếp từng thành phần của JWT:

```bash
# Trích xuất Header dưới dạng JSON
jwt-debugger header "$TOKEN" --compact

# Trích xuất Payload dưới dạng JSON
jwt-debugger payload "$TOKEN"

# Trích xuất Chữ ký dưới các định dạng mã hóa khác nhau
jwt-debugger signature "$TOKEN" --hex
jwt-debugger signature "$TOKEN" --base64
jwt-debugger signature "$TOKEN" --base64url
jwt-debugger signature "$TOKEN" --raw > signature.bin
```

---

### 5. Thao Tác Với JWK & JWKS (`jwk`)

```bash
# Kiểm tra nội dung file JWK hoặc JWKS cục bộ
jwt-debugger jwk inspect ./jwks.json

# Xác thực token trực tiếp bằng file JWK
jwt-debugger jwk verify "$TOKEN" --alg HS256 --jwk ./key.json
```

---

### 6. Tự Động Hoàn Thành Lệnh (`completion`)

Sinh script autocompletion cho shell của bạn:

```bash
# Bash
jwt-debugger completion bash > ~/.local/share/bash-completion/completions/jwt-debugger

# Zsh
jwt-debugger completion zsh > ~/.zsh/completion/_jwt-debugger

# Fish
jwt-debugger completion fish > ~/.config/fish/completions/jwt-debugger.fish
```

---

## Tự Động Hóa & Pipeline UNIX

### Trích xuất thông tin claims qua `jq`

```bash
echo "$TOKEN" | jwt-debugger payload --json | jq '.user_id'
```

### Kiểm tra xác thực token trong kịch bản shell / pipeline CI

```bash
if jwt-debugger verify "$TOKEN" --alg RS256 --public-key ./key.pem --quiet; then
    echo "Xác thực thành công"
else
    echo "Token không hợp lệ hoặc đã hết hạn"
    exit 1
fi
```

---

## Bảng Mã Thoát Tiến Trình (Exit Codes)

`jwt-debugger` trả về các mã thoát chuẩn xác phục vụ việc viết kịch bản tự động hóa:

| Mã Thoát | Tên Định Danh | Mô Tả |
| :---: | :--- | :--- |
| **`0`** | `EXIT_SUCCESS` | Thành công; chữ ký hợp lệ và tất cả các claim đều vượt qua kiểm tra. |
| **`1`** | `EXIT_GENERIC_ERROR` | Lỗi thực thi không xác định. |
| **`2`** | `EXIT_INVALID_USAGE` | Tham số dòng lệnh không hợp lệ hoặc có xung đột cờ. |
| **`3`** | `EXIT_MALFORMED_JWT` | Chuỗi JWT sai cấu trúc hoặc không đủ 3 phân đoạn. |
| **`4`** | `EXIT_SIGNATURE_INVALID` | Chữ ký mật mã học không khớp hoặc không hợp lệ. |
| **`5`** | `EXIT_CLAIMS_INVALID` | Ràng buộc claims thất bại (token hết hạn, sai issuer/audience). |
| **`6`** | `EXIT_KEY_ERROR` | Lỗi khóa (không đọc được file, định dạng PEM/JWK không đúng). |
| **`7`** | `EXIT_NETWORK_ERROR` | Lỗi kết nối mạng khi tải JWKS từ xa. |

---

## Sử Dụng Thư Viện Rust SDK

`jwt-debugger` cũng là một crate thư viện Rust hiệu năng cao.

Thêm vào file `Cargo.toml`:

```toml
[dependencies]
jwt-debugger = "0.1"
```

### Ví dụ: Xác Thực Chữ Ký và Kiểm Tra Claims

```rust
use chrono::Utc;
use std::time::Duration;
use jwt_debugger::{
    JwtToken, JwtAlgorithm, VerificationKey, HmacKey,
    VerificationOptions, ClaimValidationOptions, verify_jwt
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let raw = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
    let token = JwtToken::parse(raw)?;

    let key = VerificationKey::Hmac(HmacKey::new(b"your-256-bit-secret".to_vec()));
    let ver_opts = VerificationOptions::default();
    let claim_opts = ClaimValidationOptions {
        subject: Some("1234567890".to_string()),
        leeway: Duration::from_secs(30),
        ..Default::default()
    };

    let report = verify_jwt(
        &token,
        JwtAlgorithm::HS256,
        &key,
        &ver_opts,
        &claim_opts,
        Utc::now(),
    );

    if report.valid {
        println!("JWT hợp lệ! Subject: {:?}", token.claims.sub);
    } else {
        eprintln!("Xác thực thất bại: {:?}", report.signature.error);
    }

    Ok(())
}
```

---

## Bộ Tài Liệu Chuyên Sâu Về JWT & JOSE

Để tìm hiểu chi tiết toàn diện từ lý thuyết mật mã học đến kiến trúc triển khai thực tế, bạn có thể tham khảo [Bộ Tài Liệu Kỹ Thuật (Tiếng Việt)](docs/README.md):

- [Chương 1: Tổng Quan & Kiến Trúc (Stateful vs Stateless, JWS vs JWE)](docs/01-tong-quan-va-kien-truc.md)
- [Chương 2: Cấu Trúc Phân Đoạn & Mã Hóa Base64URL](docs/02-cau-truc-va-ma-hoa-base64url.md)
- [Chương 3: Các Thuật Toán Ký Số JWA (HMAC, RSA, ECDSA, EdDSA)](docs/03-cac-thuat-toan-ky-jwa.md)
- [Chương 4: Tiêu Chuẩn JWK & JWKS (OIDC Discovery, Zero-Downtime Key Rotation)](docs/04-tieu-chuan-jwk-va-jwks.md)
- [Chương 5: Các Lỗ Hổng Bảo Mật Kinh Điển & Chiến Lược Phòng Thủ](docs/05-cac-lo-hong-bao-mat-kinh-dien.md)
- [Chương 6: Best Practices & Chuẩn Kiến Trúc Triển Khai Thực Tế](docs/06-best-practices-va-chuan-trien-khai.md)
- [Chương 7: Sổ Tay Thực Chiến & Kiểm Thử với jwt-debugger CLI](docs/07-so-tay-thuc-chien-jwt-debugger.md)

---

## Tiêu Chuẩn & Đặc Tả Kỹ Thuật (RFC)

- **[RFC 7519](https://datatracker.ietf.org/doc/html/rfc7519)**: JSON Web Token (JWT)
- **[RFC 7515](https://datatracker.ietf.org/doc/html/rfc7515)**: JSON Web Signature (JWS)
- **[RFC 7517](https://datatracker.ietf.org/doc/html/rfc7517)**: JSON Web Key (JWK)
- **[RFC 7518](https://datatracker.ietf.org/doc/html/rfc7518)**: JSON Web Algorithms (JWA)
- **[RFC 8037](https://datatracker.ietf.org/doc/html/rfc8037)**: CFRG Elliptic Curve Diffie-Hellman (ECDH) and Signatures in JOSE (Ed25519)

---

## Giấy Phép

Dự án được phân phối theo [Giấy phép MIT](LICENSE).
