# JWT Fuzz Tool

A JWT security testing tool that generates attack payloads for known JWT vulnerabilities and supports signature brute forcing using dictionary attacks.

## Features

- **Signature Brute Force**: Dictionary attack on JWT HMAC signatures (HS256, HS512)
- **Vulnerability Payload Generation**: Generate exploit payloads for known CVEs:
  - CVE-2015-2951: None Algorithm bypass
  - CVE-2016-10555: Algorithm confusion (RS256 → HS256)
  - CVE-2018-0114: JWK key injection
  - CVE-2019-20933/CVE-2020-28637: Blank password
  - CVE-2020-28042: Null signature
  - CVE-2022-21449: Psychic signatures (ECDSA bypass)

## Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/jwt_fuzz_tool.git
cd jwt_fuzz_tool

# Build the tool
go build -o jwt_fuzz_tool main.go
```

## Usage

### Generate Attack Payloads

```bash
./jwt_fuzz_tool -jwt "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
```

### Brute Force JWT Signature

```bash
./jwt_fuzz_tool -jwt "your.jwt.token" -fuzz
```

The tool will use the dictionary file at `dict/fuzz.txt` to attempt brute forcing the JWT signature.

## Dictionary File

Place your password dictionary at `dict/fuzz.txt`. The tool will test each line as a potential HMAC secret key.

Example dictionary format:
```
secret
password
admin123
key123
```

## Attack Modes

The tool generates the following attack payloads automatically:

### 1. None Algorithm Attack (CVE-2015-2951)
Changes algorithm to "none" and removes signature, exploiting servers that don't properly verify the algorithm.

### 2. Algorithm Confusion (CVE-2016-10555)
Changes RS256 to HS256 and uses the server's public key as the HMAC secret.

### 3. Key Injection (CVE-2018-0114)
Injects a JWK (JSON Web Key) into the header with a known attacker-controlled key.

### 4. Blank Password (CVE-2019-20933)
Uses an empty string as the HMAC secret for signing.

### 5. Null Signature (CVE-2020-28042)
Generates tokens with empty or null-byte signatures.

### 6. Psychic Signature (CVE-2022-21449)
Exploits Java ECDSA implementation vulnerability by using r=0, s=0 signature.

## Requirements

- Go 1.25.5 or higher

## Legal Disclaimer

This tool is intended for authorized security testing and educational purposes only. Users must obtain proper authorization before testing any systems. The authors are not responsible for any misuse of this tool.

## License

MIT License