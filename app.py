import os
import re
import time
import json
import socket
import ipaddress
from collections import defaultdict, deque
from datetime import datetime, timezone
from urllib.parse import urljoin, urlparse, urlunparse

import requests
from bs4 import BeautifulSoup
from flask import Flask, render_template, request, jsonify, session
from werkzeug.middleware.proxy_fix import ProxyFix

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY") or os.urandom(32)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1)

# A private access key is required in Render environment variables.
ACCESS_KEY = os.environ.get("SCANNER_ACCESS_KEY", "").strip()
MAX_PAGES = 10
MAX_BODY_BYTES = 450_000
REQUEST_TIMEOUT = 7
USER_AGENT = "NIGHT-HEX-Responsible-Audit/3.0"
SCAN_COOLDOWN_SECONDS = 15
_recent_scans = defaultdict(float)


def is_public_ip(value: str) -> bool:
    try:
        ip = ipaddress.ip_address(value)
        return ip.is_global
    except ValueError:
        return False


def validate_target(raw: str, expected_host: str | None = None) -> dict:
    raw = (raw or "").strip()
    if len(raw) > 2048:
        raise ValueError("URL is too long.")
    if not re.match(r"^https?://", raw, re.I):
        raw = "https://" + raw
    p = urlparse(raw)
    if p.scheme.lower() not in ("http", "https") or not p.hostname:
        raise ValueError("Enter a valid public http:// or https:// URL.")
    if p.username or p.password:
        raise ValueError("URLs containing usernames or passwords are not allowed.")
    host = p.hostname.rstrip(".").lower()
    if host in ("localhost",) or host.endswith((".localhost", ".local", ".internal", ".test")):
        raise ValueError("Local and internal hostnames are blocked.")
    port = p.port or (443 if p.scheme.lower() == "https" else 80)
    if (p.scheme.lower(), port) not in (("http", 80), ("https", 443)):
        raise ValueError("Only standard HTTP (80) and HTTPS (443) ports are allowed.")
    if expected_host and host != expected_host:
        raise ValueError("Crawling is restricted to the original hostname.")
    try:
        # Reject any hostname that resolves to a private, loopback, link-local,
        # reserved, or otherwise non-global address.
        if is_public_ip(host):
            addresses = [host]
        else:
            infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
            addresses = list({item[4][0] for item in infos})
        if not addresses or any(not is_public_ip(ip) for ip in addresses):
            raise ValueError("Private, local, or reserved network targets are blocked.")
    except socket.gaierror:
        raise ValueError("Could not resolve the domain.")
    path = p.path or "/"
    clean = urlunparse((p.scheme.lower(), p.netloc, path, "", p.query, ""))
    return {"url": clean, "host": host, "scheme": p.scheme.lower(), "port": port}


def fetch_passive(url: str, expected_host: str) -> dict:
    target = validate_target(url, expected_host)
    # Requests follows no redirects; each target is validated separately.
    # Do not use environment proxies or credentials from the host environment.
    with requests.Session() as s:
        s.trust_env = False
        s.headers.update({"User-Agent": USER_AGENT, "Accept": "text/html,application/xhtml+xml,*/*;q=0.5"})
        try:
            with s.get(target["url"], timeout=(4, REQUEST_TIMEOUT), allow_redirects=False,
                       stream=True, verify=True) as response:
                body = bytearray()
                content_type = response.headers.get("Content-Type", "")
                if "text/html" in content_type.lower() or not content_type:
                    for chunk in response.iter_content(chunk_size=8192):
                        if not chunk:
                            continue
                        remaining = MAX_BODY_BYTES - len(body)
                        if remaining <= 0:
                            break
                        body.extend(chunk[:remaining])
                        if len(body) >= MAX_BODY_BYTES:
                            break
                return {
                    "url": target["url"],
                    "status": response.status_code,
                    "headers": {k.lower(): v for k, v in response.headers.items()},
                    "body": bytes(body).decode(response.encoding or "utf-8", errors="replace"),
                    "content_type": content_type or "Not provided",
                    "elapsed": round(response.elapsed.total_seconds(), 2),
                    "location": response.headers.get("Location", ""),
                    "final_url": target["url"],
                }
        except requests.RequestException as exc:
            raise ValueError(f"Request failed (network or TLS): {str(exc)[:180]}")


def add_check(checks, area, name, severity, status, detail, fix=""):
    checks.append({
        "area": area, "name": name, "severity": severity,
        "status": status, "detail": detail, "fix": fix
    })


def normalize_link(href: str, base_url: str, original_host: str):
    if not href:
        return None
    href = href.strip()
    if href.startswith(("#", "javascript:", "mailto:", "tel:", "data:", "blob:")):
        return None
    absolute = urljoin(base_url, href)
    try:
        parsed = validate_target(absolute)
    except (ValueError, Exception):
        return None
    if parsed["host"] != original_host:
        return {"external_host": parsed["host"]}
    # Skip common static assets and query-heavy URLs to keep crawl bounded.
    if re.search(r"\.(png|jpe?g|gif|svg|css|js|ico|woff2?|pdf|zip|mp4|webm)(?:$|\?)", parsed["url"], re.I):
        return None
    return {"url": parsed["url"]}


def perform_scan(raw_url):
    initial = validate_target(raw_url)
    host = initial["host"]
    root = fetch_passive(initial["url"], host)
    queue = deque([initial["url"]])
    seen = set()
    pages, forms, external_hosts, redirects = [], [], set(), []
    while queue and len(pages) < MAX_PAGES:
        current = queue.popleft()
        if current in seen:
            continue
        seen.add(current)
        try:
            result = root if current == initial["url"] else fetch_passive(current, host)
        except ValueError as exc:
            pages.append({"url": current, "status": "ERROR", "error": str(exc)})
            continue
        pages.append({
            "url": current, "status": result["status"],
            "content_type": result["content_type"], "elapsed": result["elapsed"]
        })
        if result["location"]:
            redirects.append({"url": current, "status": result["status"], "location": result["location"]})
        content_type = result["content_type"].lower()
        body = result["body"]
        if "html" not in content_type and not re.search(r"<\s*(html|form|a|script)\b", body, re.I):
            continue
        soup = BeautifulSoup(body, "html.parser")
        for form in soup.find_all("form")[:100]:
            fields = []
            for el in form.find_all(["input", "textarea", "select", "button"])[:60]:
                fields.append({
                    "name": (el.get("name") or "")[:80],
                    "type": (el.get("type") or el.name or "text")[:30]
                })
            forms.append({
                "page": current, "method": (form.get("method") or "GET").upper(),
                "action": (form.get("action") or ""),
                "fields": fields
            })
        for el in soup.find_all(["a", "link"], href=True):
            item = normalize_link(el.get("href"), current, host)
            if not item:
                continue
            if "external_host" in item:
                external_hosts.add(item["external_host"])
            elif item["url"] not in seen and item["url"] not in queue and len(queue) + len(pages) < MAX_PAGES * 2:
                queue.append(item["url"])

    checks = []
    https = initial["scheme"] == "https"
    add_check(checks, "Transport", "HTTPS", "high", "PASS" if https else "REVIEW",
              "The target URL uses HTTPS and certificate verification was enabled." if https
              else "The submitted URL uses HTTP without transport encryption.",
              "" if https else "Enable HTTPS with a valid certificate and redirect HTTP to HTTPS.")
    headers = root["headers"]
    header_specs = [
        ("strict-transport-security", "HSTS", "medium", "Enable HSTS after confirming HTTPS works across the site."),
        ("content-security-policy", "Content-Security-Policy", "medium", "Create a suitable CSP and avoid unsafe-inline/unsafe-eval where feasible."),
        ("x-content-type-options", "X-Content-Type-Options", "low", "Set X-Content-Type-Options: nosniff."),
        ("referrer-policy", "Referrer-Policy", "low", "Set a suitable Referrer-Policy, such as strict-origin-when-cross-origin."),
        ("permissions-policy", "Permissions-Policy", "low", "Restrict browser capabilities the application does not need."),
    ]
    for key, label, severity, fix in header_specs:
        present = bool(headers.get(key))
        add_check(checks, "Headers", label, severity, "PASS" if present else "REVIEW",
                  "Header observed in the root response." if present
                  else "Header not observed in the root response; this is a hardening observation, not proof of an exploitable vulnerability.",
                  "" if present else fix)
    csp = headers.get("content-security-policy", "")
    frame = bool(headers.get("x-frame-options")) or "frame-ancestors" in csp.lower()
    add_check(checks, "Headers", "Clickjacking protection", "medium", "PASS" if frame else "REVIEW",
              "X-Frame-Options or CSP frame-ancestors was observed." if frame
              else "No X-Frame-Options or CSP frame-ancestors was observed in the root response.",
              "" if frame else "Set X-Frame-Options or an appropriate CSP frame-ancestors directive.")
    cookies = root["headers"].get("set-cookie", "")
    # Requests combines header values in its mapping; inspect the visible Set-Cookie string.
    cookie_flags = []
    if cookies:
        low = cookies.lower()
        if https and "secure" not in low: cookie_flags.append("Secure")
        if "httponly" not in low: cookie_flags.append("HttpOnly")
        if "samesite=" not in low: cookie_flags.append("SameSite")
    add_check(checks, "Cookies", "Cookie security flags", "medium" if cookie_flags else "info",
              "NOT OBSERVED" if not cookies else ("REVIEW" if cookie_flags else "PASS"),
              "No Set-Cookie header was observed on the root response." if not cookies
              else ("Potentially missing flags: " + ", ".join(cookie_flags) if cookie_flags
                    else "Common flags were observed in the response header."),
              "Review each cookie individually; use Secure on HTTPS, HttpOnly when JavaScript access is unnecessary, and a suitable SameSite value." if cookie_flags else "")
    server = headers.get("server", "")
    powered = headers.get("x-powered-by", "")
    add_check(checks, "Disclosure", "Server technology disclosure", "low",
              "REVIEW" if server or powered else "PASS",
              (f"Response headers disclose Server: {server or 'not set'}; X-Powered-By: {powered or 'not set'}."
               if server or powered else "No Server or X-Powered-By value was observed."),
              "Minimize unnecessary product/version disclosure." if server or powered else "")
    add_check(checks, "Discovery", "Same-origin page discovery", "info", "INFO",
              f"Visited {len(pages)} page(s), found {len(forms)} form(s), and observed {len(external_hosts)} external host(s). Forms were not submitted and redirects were not followed.")
    password_fields = sum(1 for f in forms for field in f["fields"] if field["type"].lower() == "password")
    post_forms = sum(1 for f in forms if f["method"] == "POST")
    add_check(checks, "Application map", "Form inventory", "info", "INFO",
              f"Found {len(forms)} form(s), {password_fields} password input(s), and {post_forms} POST form(s). Inventory only; no login attempts were made.")
    if initial["scheme"] == "http" and password_fields:
        add_check(checks, "Transport", "Password field served over HTTP", "high", "REVIEW",
                  "A password input was observed on a page served over HTTP.",
                  "Serve login pages only over HTTPS and ensure form actions also use HTTPS.")

    counts = {"high": 0, "medium": 0, "low": 0}
    for c in checks:
        if c["severity"] in counts and c["status"] == "REVIEW":
            counts[c["severity"]] += 1
    return {
        "product": "NIGHT HEX Advanced", "version": "3.0",
        "target": initial["url"], "host": host,
        "checked_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        "http_status": root["status"], "content_type": root["content_type"],
        "response_time": root["elapsed"], "pages": pages, "forms": forms,
        "redirects": redirects, "external_hosts": sorted(external_hosts),
        "summary": {**counts, "pages_crawled": len(pages), "forms_found": len(forms)},
        "checks": checks,
        "limitations": "Bounded passive assessment only. No exploitation, password guessing, login attempts, form submission, arbitrary file probing, or access-control bypass. Findings are observations requiring human validation; this is not a full penetration test."
    }


@app.get("/")
def index():
    return render_template("index.html", channel_url="https://t.me/+qFllt01YeXk2YzQ1", telegram_url="https://t.me/NightHex_X")


@app.post("/api/scan")
def api_scan():
    if not ACCESS_KEY:
        return jsonify(error="Scanner is not configured yet. Set SCANNER_ACCESS_KEY in the hosting environment."), 503
    payload = request.get_json(silent=True) or {}
    submitted_key = str(payload.get("access_key", ""))
    if not (len(submitted_key) == len(ACCESS_KEY) and __import__("hmac").compare_digest(submitted_key, ACCESS_KEY)):
        return jsonify(error="Access key is incorrect."), 403
    if not payload.get("authorized"):
        return jsonify(error="Confirm you own the site or have explicit permission to assess it."), 400
    client = request.headers.get("X-Forwarded-For", request.remote_addr or "unknown").split(",")[0].strip()
    now = time.time()
    if now - _recent_scans[client] < SCAN_COOLDOWN_SECONDS:
        return jsonify(error="Please wait at least 15 seconds between scans."), 429
    _recent_scans[client] = now
    try:
        report = perform_scan(str(payload.get("url", "")))
        return jsonify(result=report)
    except (ValueError, requests.RequestException) as exc:
        return jsonify(error=str(exc)[:300]), 400
    except Exception:
        app.logger.exception("Unexpected scan error")
        return jsonify(error="Unexpected server error. Check the Render logs."), 500


@app.get("/healthz")
def health():
    return jsonify(status="ok", service="night-hex-advanced")


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "5000")), debug=False)
