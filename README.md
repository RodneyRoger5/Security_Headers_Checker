# 🛡️ Security Headers Checker

A lightweight Python CLI tool that scans any website's HTTP response and
reports on its security headers, information-disclosure leaks, and caching
configuration — with a clean, color-coded terminal report and an overall
security grade (A–F).

## Why

Security headers like `Content-Security-Policy` and
`Strict-Transport-Security` are one of the cheapest ways to harden a website
against XSS, clickjacking, and MIME-sniffing attacks — but they're easy to
forget. This tool gives you a quick, readable snapshot of what's set and
what's missing.

## Features

- ✅ Checks 12 key security headers (HSTS, CSP, X-Frame-Options, Permissions-Policy, COOP/COEP/CORP, and more)
- 🕵️ Flags information-disclosure headers (`Server`, `X-Powered-By`, etc.)
- 📦 Reports cache-control behavior (`Cache-Control`, `Pragma`, `Expires`)
- 📊 Weighted scoring with a visual progress bar and letter grade
- 🔗 Supports scanning multiple URLs in one run, with a summary table
- 🎨 Color-coded terminal output (falls back gracefully without `colorama`)

## Installation

```bash
git clone https://github.com/<your-username>/security-headers-checker.git
cd security-headers-checker
pip install -r requirements.txt
```

## Usage

```bash
python security_headers_checker.py example.com
python security_headers_checker.py https://example.com https://another-site.org
python security_headers_checker.py example.com --timeout 15
```

### Example output

```
╭────────────────────────────────────────────────────────────────╮
│ Target: https://example.com                                     │
╰────────────────────────────────────────────────────────────────╯

┄┄┄ Security Headers ┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄
  ✓ Strict-Transport-Security         max-age=15552000; preload
  ✗ Content-Security-Policy           missing [MED]
  ...

┄┄┄ Score ┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄
  ████████████░░░░░░░░░░░░  58%   grade: C
```

## Headers checked

| Header | Severity if missing |
|---|---|
| Strict-Transport-Security | High |
| Content-Security-Policy | Medium |
| X-Frame-Options | Medium |
| X-Content-Type-Options | Medium |
| Referrer-Policy | Medium |
| Permissions-Policy | Medium |
| Cross-Origin-Opener-Policy | Medium |
| Cross-Origin-Embedder-Policy | Medium |
| Cross-Origin-Resource-Policy | Medium |
| X-XSS-Protection | Low (deprecated) |
| X-Permitted-Cross-Domain-Policies | Low (deprecated) |
| Expect-CT | Low (deprecated) |

## Roadmap

- [ ] JSON / CSV export
- [ ] Header *value* validation (e.g. flag `X-Frame-Options: ALLOWALL`)
- [ ] CI mode with exit codes for use in pipelines

## Disclaimer

This tool only inspects publicly served HTTP response headers. Only scan
domains you own or have permission to test.

## License

[MIT](LICENSE)
