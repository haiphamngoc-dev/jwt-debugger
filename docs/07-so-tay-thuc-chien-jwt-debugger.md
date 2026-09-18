# Chương 7: Sổ Tay Thực Chiến và Kiểm Thử với JWT Debugger CLI

`jwt-debugger` là công cụ dòng lệnh (CLI) hiệu năng cao được viết bằng ngôn ngữ Rust, hỗ trợ toàn diện các thao tác giải mã, phân tích cấu trúc, kiểm tra tính toàn vẹn mật mã học và tạo mới token cho mọi thuật toán trong hệ sinh thái JOSE.

Chương này là sổ tay tra cứu thực chiến dành cho các kỹ sư DevSecOps, Backend Developer và Security Researcher.

---

## 1. Phân Tích và Giải Mã Token (Decode & Inspect)

### 1.1. Giải mã cơ bản và hiển thị định dạng trực quan

```bash
jwt-debugger decode --jwt "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
```

### 1.2. Trích xuất từng phần để kết hợp với `jq` trong pipeline

```bash
# Trích xuất riêng phần Payload dưới định dạng JSON thuần
jwt-debugger decode --jwt "$TOKEN" --part payload --format json | jq '.sub'

# Trích xuất riêng phần Header
jwt-debugger decode --jwt "$TOKEN" --part header --format json | jq '.alg'

# Trích xuất thông tin thời gian hết hạn đã chuyển đổi sang định dạng UTC ISO8601
jwt-debugger decode --jwt "$TOKEN" --inspect-dates
```

---

## 2. Xác Thực Chữ Ký Mật Mã Học (Signature Verification)

### 2.1. Xác thực chữ ký đối xứng HMAC (HS256, HS384, HS512)

```bash
# Xác thực với chuỗi khóa bí mật trực tiếp
jwt-debugger verify --jwt "$TOKEN" --secret "your-256-bit-secret-string-here"

# Xác thực với chuỗi bí mật đã mã hóa Base64
jwt-debugger verify --jwt "$TOKEN" --secret-base64 "eW91ci1zZWNyZXQta2V5LWRhdGE="

# Xác thực với khóa bí mật lưu trong tập tin
jwt-debugger verify --jwt "$TOKEN" --secret-file /path/to/secret.key
```

### 2.2. Xác thực chữ ký bất đối xứng RSA (RS256, PS256,...)

```bash
# Xác thực bằng tập tin Khóa công khai định dạng PEM
jwt-debugger verify --jwt "$TOKEN" --public-key-file ./public_key.pem

# Xác thực kèm kiểm tra nghiêm ngặt Issuer, Audience và khoảng dung sai thời gian
jwt-debugger verify --jwt "$TOKEN" \
  --public-key-file ./public_key.pem \
  --issuer "https://auth.company.com" \
  --audience "api.company.com" \
  --leeway 30
```

### 2.3. Xác thực chữ ký đường cong Elliptic (ECDSA & EdDSA)

```bash
# Xác thực thuật toán ES256 (NIST P-256)
jwt-debugger verify --jwt "$TOKEN" --public-key-file ./ec_public.pem

# Xác thực thuật toán Ed25519 (RFC 8037)
jwt-debugger verify --jwt "$TOKEN" --public-key-file ./ed25519_public.pem
```

### 2.4. Xác thực tự động qua Endpoint JWKS từ xa

```bash
jwt-debugger verify --jwt "$TOKEN" \
  --jwks-url "https://login.microsoftonline.com/common/discovery/v2.0/keys"
```

---

## 3. Sinh Cặp Khóa Mật Mã Học (Key Generation)

`jwt-debugger` hỗ trợ sinh các cặp khóa bảo mật cao theo tiêu chuẩn IETF và xuất ra định dạng PEM hoặc JWK/JWKS.

### 3.1. Sinh cặp khóa Ed25519 (Khuyến nghị cho kiến trúc mới)

```bash
# Xuất ra tập tin PEM
jwt-debugger keygen --algorithm Ed25519 --out-private ed_priv.pem --out-public ed_pub.pem

# Xuất trực tiếp ra định dạng JSON Web Key (JWK)
jwt-debugger keygen --algorithm Ed25519 --format jwk --kid "ed-key-01"
```

### 3.2. Sinh cặp khóa RSA 4096-bit

```bash
jwt-debugger keygen --algorithm RSA --bits 4096 --out-private rsa_priv.pem --out-public rsa_pub.pem
```

### 3.3. Sinh cặp khóa ECDSA P-256 và xuất tập tin JWKS

```bash
jwt-debugger keygen --algorithm ES256 --format jwk-set --out-jwks ./jwks.json
```

---

## 4. Ký và Ban Hành Token Mới (Token Issuance / Signing)

### 4.1. Ký token bằng thuật toán HMAC-SHA256

```bash
jwt-debugger sign \
  --algorithm HS256 \
  --secret "super-secret-key-32-bytes-minimum" \
  --subject "user-9912" \
  --issuer "https://auth.internal" \
  --audience "https://api.internal" \
  --expires-in 3600 \
  --claim "role=admin" \
  --claim "department=engineering"
```

### 4.2. Ký token RSA-PSS (PS256) với tập tin Claims JSON tùy biến

```bash
jwt-debugger sign \
  --algorithm PS256 \
  --private-key-file ./rsa_private.pem \
  --payload-file ./claims.json \
  --kid "rsa-pss-key-01"
```

---

## 5. Tích Hợp Kiểm Thử Tự Động Trong CI/CD Pipeline

Có thể tích hợp `jwt-debugger` vào quy trình tích hợp liên tục (GitHub Actions, GitLab CI) để kiểm tra tính hợp lệ của token hoặc rà soát các token kiểm thử tự động.

### 5.1. Kịch bản kiểm tra an ninh trong Shell Script

```bash
#!/usr/bin/env bash
set -euo pipefail

# 1. Kiểm tra thuật toán: Không được phép sử dụng "none" hoặc "HS256" trong môi trường bất đối xứng
ALG=$(jwt-debugger decode --jwt "$STAGING_TOKEN" --part header --format json | jq -r '.alg')

if [ "$ALG" = "none" ] || [ "$ALG" = "HS256" ]; then
    echo "VI PHẠM AN NINH: Token đang sử dụng thuật toán bị cấm ($ALG)" >&2
    exit 1
fi

# 2. Xác thực chữ ký với Khóa công khai của môi trường Staging
if ! jwt-debugger verify --jwt "$STAGING_TOKEN" --public-key-file ./staging_pub.pem --leeway 10; then
    echo "THẤT BẠI: Chữ ký JWT không hợp lệ hoặc token đã quá hạn sử dụng" >&2
    exit 1
fi

echo "THÀNH CÔNG: Token hợp lệ và vượt qua toàn bộ các bài kiểm tra an ninh."
```

### 5.2. Tích hợp vào GitHub Actions Workflow

```yaml
name: Security Token Verification Test

on: [push, pull_request]

jobs:
  verify-tokens:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Download jwt-debugger Release
        run: |
          curl -sSL -O https://github.com/haiphamngoc-dev/jwt-debugger/releases/download/v0.1.0/jwt-debugger-linux-x86_64.tar.gz
          tar -xzf jwt-debugger-linux-x86_64.tar.gz
          sudo mv jwt-debugger /usr/local/bin/
          jwt-debugger --version

      - name: Run JWT Verification Test Suite
        run: |
          jwt-debugger verify \
            --jwt "${{ secrets.INTEGRATION_TEST_JWT }}" \
            --jwks-url "${{ secrets.STAGING_OIDC_JWKS_URL }}" \
            --issuer "https://staging-auth.example.com"
```
