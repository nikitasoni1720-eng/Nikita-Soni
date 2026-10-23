# WebScanner: Automated HTTP Security Headers & CORS Auditor

A modular, production-ready Python tool to audit web applications and APIs for secure HTTP headers, technology information disclosure, and Cross-Origin Resource Sharing (CORS) misconfigurations according to OWASP security best practices.

---

## Features

- **Standard HTTP Security Header Verification**:
  - `Strict-Transport-Security` (HSTS): Validates `max-age` duration, `includeSubDomains`, and `preload`.
  - `Content-Security-Policy` (CSP): Detects missing policies, unsafe directives (`'unsafe-inline'`, `'unsafe-eval'`), and missing fallbacks.
  - `X-Frame-Options` & CSP `frame-ancestors`: Checks clickjacking protections and flags deprecated directives (like `ALLOW-FROM`).
  - `X-Content-Type-Options`: Confirms `nosniff` enforcement against MIME sniffing.
  - `Referrer-Policy`: Flags insecure values (`unsafe-url`, `no-referrer-when-downgrade`).
  - `Permissions-Policy` (formerly `Feature-Policy`): Assesses restrictions on device APIs (camera, microphone, geolocation).
  - Cross-Origin Policies: Inspects `Cross-Origin-Opener-Policy` (COOP) and `Cross-Origin-Resource-Policy` (CORP).

- **In-Depth CORS Vulnerability Auditing**:
  - **Static Inspection**: Flags wildcard origins (`*`) combined with credentials or sensitive endpoints.
  - **Arbitrary Origin Reflection**: Probes whether custom attacker origins (`Origin: https://evil-attacker.example.com`) are dynamically reflected in `Access-Control-Allow-Origin`.
  - **Null Origin Trust**: Tests if `Origin: null` is accepted, mitigating sandboxed iframe exploits.
  - **Credentialed Access Validation**: Flags `Access-Control-Allow-Credentials: true` with unsafe origins.
  - **Sensitive Header Leakage**: Checks `Access-Control-Expose-Headers` for `Set-Cookie`, `Authorization`, or tokens.
  - **Preflight Inspection**: Probes HTTP `OPTIONS` requests for dangerous methods (`PUT`, `DELETE`).

- **Information Disclosure Detection**:
  - Flags server banners and framework disclosures (`Server`, `X-Powered-By`, `X-AspNet-Version`, `X-Generator`).

- **Executive Scoring & Grading**:
  - Generates a numeric security score (0–100) and letter grade (`A+`, `A`, `B`, `C`, `D`, `F`).

- **Flexible Output Formats**:
  - Formatted, color-coded terminal reports with action-oriented remediation advice.
  - Machine-readable JSON export (`--output results.json`).
  - Human-readable Plain Text export (`--output results.txt`).

---

## File Structure

```
WebScanner/
├── config.py           # Configuration, header rules, weights, and test origins
├── http_client.py      # HTTP client handling GET/OPTIONS, timeouts, and redirects
├── header_scanner.py   # Core audit engine for security headers and CORS
├── reporter.py         # Console output (colorized) and file exporters (JSON, TXT)
├── logger.py           # Centralized logging setup
├── main.py             # CLI entry point, argument parsing, and batch runner
├── requirements.txt    # Project dependencies
└── README.md           # Documentation and security guide
```

---

## Installation

### 1. Prerequisites
- Python 3.8 or higher.

### 2. Clone or Navigate to the Project Directory
```powershell
cd "C:\Users\Nikita Soni\.gemini\antigravity\scratch\WebScanner"
```

### 3. Create and Activate a Virtual Environment
```powershell
# Windows
python -m venv venv
.\venv\Scripts\activate
```

### 4. Install Dependencies
```powershell
pip install -r requirements.txt
```

---

## Usage Guide

### 1. Interactive Mode
If no flags are passed, WebScanner will prompt you for a target URL:
```powershell
python main.py
```

### 2. Scan a Single Target
Scan any website directly via the command-line:
```powershell
python main.py -u https://example.com
```

### 3. Batch Scan Multiple URLs from a File
Create a text file (e.g., `targets.txt`) with one URL per line:
```
https://example.com
https://github.com
https://httpbin.org
```
Run the batch scan:
```powershell
python main.py -f targets.txt
```

### 4. Exporting Scan Results
Export the audit report to a structured JSON file:
```powershell
python main.py -u https://example.com -o report.json
```
Export to a plain text file:
```powershell
python main.py -u https://example.com -o report.txt --format txt
```

### 5. Advanced Flags
| Flag | Description |
|---|---|
| `-u, --url` | Target URL to audit |
| `-f, --file` | File containing multiple target URLs (one per line) |
| `-o, --output` | File path to export results (`.json` or `.txt`) |
| `--format` | Explicit report format: `json` or `txt` |
| `--timeout` | HTTP request timeout in seconds (default: `10`) |
| `--user-agent` | Custom `User-Agent` string |
| `--no-cors` | Skip active CORS probing (evaluates only static headers) |
| `--insecure` | Bypass SSL certificate verification (useful for internal staging) |
| `--no-color` | Disable ANSI color codes in console output |
| `-v, --verbose` | Enable verbose / debug logging |
| `--log-file` | File path for log records (default: `webscanner.log`) |

---

## CORS Flaws Detected & Remediations

| Misconfiguration | Risk Level | Description | Remediation |
|---|---|---|---|
| **Arbitrary Origin Reflection with Credentials** | `CRITICAL` | Server echoes back any request `Origin` and sets `Access-Control-Allow-Credentials: true`. Any attacker site can access user data. | Maintain a strict server-side whitelist of allowed origins. Never mirror the `Origin` header dynamically. |
| **Wildcard Origin (`*`) with Credentials** | `CRITICAL` | Server returns both `*` and `Allow-Credentials: true`. Modern browsers reject this, but it reflects flawed security logic. | Disallow credentials when using wildcard origins. Use specific origins. |
| **Null Origin Allowed (`null`)** | `HIGH` | Origin `null` is trusted. Sandboxed iframes (`<iframe sandbox>`) send `null` and can bypass restrictions. | Remove `null` from the origin whitelist. |
| **Sensitive Headers Exposed** | `HIGH` | `Access-Control-Expose-Headers` exposes cookies or auth headers (`Set-Cookie`, `Authorization`). | Expose only non-sensitive application headers. |
| **State-Changing Methods Permitted** | `MEDIUM` | Preflight grants `PUT`, `DELETE`, or `PATCH` cross-origin. | Enforce CSRF tokens and strict authentication on state-changing endpoints. |

---

## License
MIT License. Created for defensive security posture assessments and educational auditing.
