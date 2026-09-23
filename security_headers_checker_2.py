#!/usr/bin/env python3
"""
Web Security Headers Checker
------------------------------
Scans a target URL's HTTP response headers and reports on security
posture: missing protections, info-disclosure leaks, and caching config.

Usage:
    python security_headers_checker.py https://example.com
    python security_headers_checker.py example.com another-site.org
"""

import argparse
import requests
from urllib.parse import urlparse

try:
    from colorama import Fore, Style, init
    init(autoreset=True)
    COLOR = True
except ImportError:
    COLOR = False


HEADERS_TO_CHECK = {
    'Strict-Transport-Security':          'error',
    'Content-Security-Policy':            'warning',
    'X-Frame-Options':                    'warning',
    'X-Content-Type-Options':             'warning',
    'Referrer-Policy':                    'warning',
    'Permissions-Policy':                 'warning',
    'Cross-Origin-Opener-Policy':         'warning',
    'Cross-Origin-Embedder-Policy':       'warning',
    'Cross-Origin-Resource-Policy':       'warning',
    'X-XSS-Protection':                  'deprecated',
    'X-Permitted-Cross-Domain-Policies': 'deprecated',
    'Expect-CT':                         'deprecated',
}

INFO_DISCLOSURE_HEADERS = ['Server', 'X-Powered-By', 'X-AspNet-Version', 'X-AspNetMvc-Version', 'X-Generator']
CACHE_HEADERS = ['Cache-Control', 'Pragma', 'Expires']

SEVERITY_TAG = {'error': 'HIGH', 'warning': 'MED', 'deprecated': 'LOW'}
SEVERITY_WEIGHT = {'error': 3, 'warning': 2, 'deprecated': 1}
SEVERITY_COLOR = {'error': 'red', 'warning': 'yellow', 'deprecated': 'cyan'}


def c(text, color):
    if not COLOR:
        return text
    m = {'red': Fore.RED, 'yellow': Fore.YELLOW, 'cyan': Fore.CYAN,
         'green': Fore.GREEN, 'blue': Fore.BLUE, 'grey': Fore.WHITE, 'bold': Style.BRIGHT}
    return m.get(color, '') + text + Style.RESET_ALL


def normalize_url(url: str) -> str:
    parsed = urlparse(url)
    if not parsed.scheme:
        url = "https://" + url
    return url


def fetch_headers(url: str, timeout: int = 10):
    try:
        resp = requests.get(url, timeout=timeout, allow_redirects=True)
        return resp.headers, resp.url, resp.status_code, None
    except requests.exceptions.SSLError as e:
        return None, None, None, f"SSL error: {e}"
    except requests.exceptions.ConnectionError as e:
        return None, None, None, f"Connection error: {e}"
    except requests.exceptions.Timeout:
        return None, None, None, "Request timed out."
    except requests.exceptions.RequestException as e:
        return None, None, None, f"Request failed: {e}"


def bar(pct, width=24):
    filled = round(width * pct / 100)
    color = 'green' if pct >= 75 else 'yellow' if pct >= 40 else 'red'
    return c('█' * filled, color) + c('░' * (width - filled), 'grey')


def section(title):
    print(f"\n{c('┄' * 3, 'blue')} {c(title, 'bold')} {c('┄' * (58 - len(title)), 'blue')}")


def scan(url: str, headers, final_url: str):
    print(c("╭" + "─" * 68 + "╮", 'blue'))
    print(f"{c('│', 'blue')} {c('Target:', 'bold')} {final_url:<57} {c('│', 'blue')}")
    if status := headers.get('_status'):
        pass
    print(c("╰" + "─" * 68 + "╯", 'blue'))

    # --- Security headers ---
    section("Security Headers")
    grade_points, grade_total = 0, 0
    missing_by_sev = {'error': [], 'warning': [], 'deprecated': []}

    for header, severity in HEADERS_TO_CHECK.items():
        grade_total += SEVERITY_WEIGHT[severity]
        value = headers.get(header)
        if value:
            grade_points += SEVERITY_WEIGHT[severity]
            print(f"  {c('✓', 'green')} {header:<36} {c(value[:40], 'grey')}")
        else:
            tag = SEVERITY_TAG[severity]
            missing_by_sev[severity].append(header)
            print(f"  {c('✗', SEVERITY_COLOR[severity])} {header:<36} {c('missing [' + tag + ']', SEVERITY_COLOR[severity])}")

    # --- Info disclosure ---
    section("Information Disclosure")
    leaks = [(h, headers[h]) for h in INFO_DISCLOSURE_HEADERS if headers.get(h)]
    if leaks:
        for h, v in leaks:
            print(f"  {c('!', 'yellow')} {h:<24} leaks: {c(v, 'yellow')}")
    else:
        print(f"  {c('✓', 'green')} No server/stack fingerprinting headers found")

    # --- Cache headers ---
    section("Cache Behavior")
    cache_found = False
    for h in CACHE_HEADERS:
        v = headers.get(h)
        if v:
            cache_found = True
            print(f"  {c('·', 'blue')} {h:<24} {v}")
    if not cache_found:
        print(f"  {c('·', 'grey')} No explicit cache-control directives set")

    # --- Score summary ---
    pct = round((grade_points / grade_total) * 100) if grade_total else 0
    letter = 'A' if pct >= 90 else 'B' if pct >= 75 else 'C' if pct >= 55 else 'D' if pct >= 35 else 'F'
    letter_color = 'green' if pct >= 75 else 'yellow' if pct >= 40 else 'red'

    section("Score")
    print(f"  {bar(pct)}  {pct}%   grade: {c(letter, letter_color)}")

    if missing_by_sev['error']:
        print(f"\n  {c('High-priority fixes:', 'red')} {', '.join(missing_by_sev['error'])}")
    if missing_by_sev['warning']:
        shown = ', '.join(missing_by_sev['warning'][:4])
        more = f" (+{len(missing_by_sev['warning']) - 4} more)" if len(missing_by_sev['warning']) > 4 else ""
        print(f"  {c('Recommended:', 'yellow')} {shown}{more}")

    print()
    return pct


def main():
    parser = argparse.ArgumentParser(description="Scan a website's security-related HTTP headers.")
    parser.add_argument("urls", nargs="+", help="One or more URLs/domains to check")
    parser.add_argument("--timeout", type=int, default=10, help="Request timeout in seconds (default: 10)")
    args = parser.parse_args()

    scores = {}
    for raw_url in args.urls:
        url = normalize_url(raw_url)
        headers, final_url, status_code, error = fetch_headers(url, timeout=args.timeout)
        if error:
            print(f"{c('✗', 'red')} Failed to scan {url}: {error}\n")
            continue
        scores[final_url] = scan(url, headers, final_url)

    if len(scores) > 1:
        section("Summary")
        for u, pct in scores.items():
            print(f"  {bar(pct, 16)}  {pct:>3}%  {u}")
        print()


if __name__ == "__main__":
    main()
