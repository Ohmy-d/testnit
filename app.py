#!/usr/bin/env python3
"""
CyberLab — Advanced Security Intelligence Platform
Real scanning using direct probes + third-party APIs.
For authorized testing of your own systems only.
"""

from flask import Flask, render_template, request, jsonify, Response, stream_with_context
import requests as http
import socket, ssl, json, re, time, threading, queue, base64, hashlib
import urllib.parse, ipaddress, subprocess, os
from pathlib import Path
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse, urljoin

app = Flask(__name__)

# ── .env persistence ───────────────────────────────────────────────────────────────────
ENV_FILE = Path(__file__).parent / ".env"

# Internal key name → .env variable name
KEY_MAP = {
    "virustotal":  "VIRUSTOTAL_KEY",
    "urlscan":     "URLSCAN_KEY",
    "abuseipdb":   "ABUSEIPDB_KEY",
    "shodan":      "SHODAN_KEY",
    "google_safe": "GOOGLE_SAFE_KEY",
}

def _parse_env(p: Path) -> dict:
    """Parse a .env file; ignore comments and blank lines."""
    out = {}
    if not p.exists():
        return out
    for line in p.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" in line:
            k, _, v = line.partition("=")
            out[k.strip()] = v.strip().strip('"\'').strip("\'")
    return out

def _load_keys() -> dict:
    """Load API keys: .env file takes priority over OS environment."""
    env = _parse_env(ENV_FILE)
    return {
        key: (env.get(env_name) or os.environ.get(env_name, "")).strip()
        for key, env_name in KEY_MAP.items()
    }

def _write_env(updates: dict):
    """Merge updates into the .env file; preserve existing values."""
    env = _parse_env(ENV_FILE)
    for key, env_name in KEY_MAP.items():
        if key in updates and updates[key].strip():
            env[env_name] = updates[key].strip()

    lines = [
        "# CyberLab API Keys",
        "# Edit this file directly — no restart needed.",
        "# The app re-reads it at the start of every scan.",
        "#",
        "# VIRUSTOTAL_KEY  → https://www.virustotal.com/gui/join-us",
        "# URLSCAN_KEY     → https://urlscan.io/user/signup",
        "# ABUSEIPDB_KEY   → https://www.abuseipdb.com/register",
        "# SHODAN_KEY      → https://account.shodan.io/register",
        "# GOOGLE_SAFE_KEY → https://developers.google.com/safe-browsing/v4/get-started",
        "",
    ]
    for env_name in KEY_MAP.values():
        val = env.get(env_name, "")
        lines.append(f"{env_name}={val}")
    ENV_FILE.write_text("\n".join(lines) + "\n", encoding="utf-8")

# Create .env on first run so the user sees it immediately
if not ENV_FILE.exists():
    _write_env({})

# Module-level cache — reloaded fresh inside each scan request
KEYS = _load_keys()


UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
      "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0 Safari/537.36")

SESSION_HDR = {
    "User-Agent": UA,
    "Accept-Language": "en-US,en;q=0.9",
    "Accept": "text/html,application/xhtml+xml,*/*;q=0.8",
}

TIMEOUT = 12

# ── Fix / remediation database ────────────────────────────────────────────────
FIXES = {
    "missing_hsts": {
        "severity": "HIGH", "title": "Missing HSTS",
        "fix": "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
        "ref": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security"
    },
    "missing_csp": {
        "severity": "HIGH", "title": "Missing Content-Security-Policy",
        "fix": "Add CSP header: Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'",
        "ref": "https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP"
    },
    "missing_xfo": {
        "severity": "MEDIUM", "title": "Clickjacking — Missing X-Frame-Options",
        "fix": "Add: X-Frame-Options: DENY  or use CSP frame-ancestors 'none'",
        "ref": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options"
    },
    "missing_xcto": {
        "severity": "MEDIUM", "title": "Missing X-Content-Type-Options",
        "fix": "Add: X-Content-Type-Options: nosniff",
        "ref": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options"
    },
    "missing_rp": {
        "severity": "LOW", "title": "Missing Referrer-Policy",
        "fix": "Add: Referrer-Policy: strict-origin-when-cross-origin",
        "ref": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy"
    },
    "server_header": {
        "severity": "LOW", "title": "Server Header Disclosure",
        "fix": "Remove or obscure the Server header in your web server config.",
        "ref": "https://owasp.org/www-project-secure-headers/"
    },
    "x_powered_by": {
        "severity": "LOW", "title": "X-Powered-By Disclosure",
        "fix": "Remove X-Powered-By header (PHP: expose_php=Off, Node: app.disable('x-powered-by'))",
        "ref": "https://owasp.org/www-project-secure-headers/"
    },
    "cors_wildcard": {
        "severity": "HIGH", "title": "CORS Wildcard (*) Misconfiguration",
        "fix": "Replace Access-Control-Allow-Origin: * with a specific trusted origin whitelist.",
        "ref": "https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS"
    },
    "cors_reflect": {
        "severity": "CRITICAL", "title": "CORS Reflects Arbitrary Origin",
        "fix": "Validate Origin against a strict allowlist. Never reflect the request Origin header.",
        "ref": "https://portswigger.net/web-security/cors"
    },
    "xss_reflected": {
        "severity": "HIGH", "title": "Reflected XSS",
        "fix": "HTML-encode all user input before rendering. Implement a strict CSP. Use a templating engine with auto-escaping.",
        "ref": "https://owasp.org/www-community/attacks/xss/"
    },
    "sqli_error": {
        "severity": "CRITICAL", "title": "SQL Injection (Error-Based)",
        "fix": "Use prepared statements / parameterized queries. Never concatenate user input into SQL. Enable error suppression in production.",
        "ref": "https://owasp.org/www-community/attacks/SQL_Injection"
    },
    "open_redirect": {
        "severity": "MEDIUM", "title": "Open Redirect",
        "fix": "Validate redirect targets against a strict allowlist. Reject absolute URLs in redirect params.",
        "ref": "https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html"
    },
    "exposed_env": {
        "severity": "CRITICAL", "title": "Exposed .env / Config File",
        "fix": "Block access to .env, config.php, and similar files at the web server level. Move secrets outside the web root.",
        "ref": "https://owasp.org/www-community/vulnerabilities/Insecure_Configuration_Management"
    },
    "exposed_git": {
        "severity": "CRITICAL", "title": "Exposed .git Repository",
        "fix": "Block access to /.git via web server config. Use gitignore and move repo outside web root.",
        "ref": "https://owasp.org/www-project-web-security-testing-guide/"
    },
    "dir_listing": {
        "severity": "MEDIUM", "title": "Directory Listing Enabled",
        "fix": "Disable directory listing: Apache: Options -Indexes | Nginx: autoindex off",
        "ref": "https://owasp.org/www-project-web-security-testing-guide/"
    },
    "ssl_expired": {
        "severity": "CRITICAL", "title": "SSL Certificate Expired",
        "fix": "Renew certificate immediately. Use Let's Encrypt for free auto-renewing certs.",
        "ref": "https://letsencrypt.org/"
    },
    "ssl_weak": {
        "severity": "HIGH", "title": "Weak TLS Protocol (TLS 1.0/1.1 or SSLv3)",
        "fix": "Disable TLS 1.0/1.1 and all SSLv2/3. Enable only TLS 1.2 and TLS 1.3.",
        "ref": "https://ssl-config.mozilla.org/"
    },
    "phishing": {
        "severity": "CRITICAL", "title": "Known Phishing / Malware Site",
        "fix": "Site is flagged by threat intelligence. Take down immediately, check for compromise, notify users, report to Google Safe Browsing.",
        "ref": "https://safebrowsing.google.com/safebrowsing/report_phish/"
    },
    "tracker_found": {
        "severity": "INFO", "title": "Third-Party Trackers Detected",
        "fix": "Review privacy policy. Consider replacing with self-hosted analytics (Plausible, Matomo). Implement consent management.",
        "ref": "https://www.privacyguides.org/"
    },
    "cryptominer": {
        "severity": "CRITICAL", "title": "Cryptominer Script Detected",
        "fix": "Remove miner script immediately. Audit all JS dependencies. Check for supply-chain compromise. Scan server for malware.",
        "ref": "https://owasp.org/www-project-web-security-testing-guide/"
    },
    "ip_abuse": {
        "severity": "HIGH", "title": "IP Flagged for Abuse",
        "fix": "Investigate server compromise. Check server logs. Consider IP change if hosting, or contact upstream if shared hosting.",
        "ref": "https://www.abuseipdb.com/"
    },
    "path_traversal": {
        "severity": "HIGH", "title": "Possible Path Traversal",
        "fix": "Validate and sanitize all file path inputs. Use basename() / realpath(). Restrict file access to intended directories.",
        "ref": "https://owasp.org/www-community/attacks/Path_Traversal"
    },
    "missing_cookie_flags": {
        "severity": "MEDIUM", "title": "Insecure Cookie Flags",
        "fix": "Set Secure, HttpOnly, and SameSite=Strict flags on all session cookies.",
        "ref": "https://owasp.org/www-community/controls/SecureCookieAttribute"
    },
}

# ── Known trackers / spyware / miners ─────────────────────────────────────────
TRACKERS = {
    "Analytics":     ["google-analytics.com","googletagmanager.com","analytics.google.com","segment.io","mixpanel.com","amplitude.com","heap.io","fullstory.com","logrocket.com","hotjar.com","clarity.ms","mouseflow.com","inspectlet.com"],
    "Advertising":   ["doubleclick.net","googlesyndication.com","facebook.net","connect.facebook.net","twitter.com/i/adsct","ads.linkedin.com","bing.com/bat","yahoo.com","outbrain.com","taboola.com","criteo.com","quantserve.com"],
    "Fingerprinting":["fingerprintjs.com","fpjs.io","threatmetrix.com","iovation.com","kount.com","signifyd.com","deviceatlas.com"],
    "Cryptominer":   ["coinhive.com","coin-hive.com","cryptonight","webmr.io","minero.cc","coinhive.min.js","cryptoloot.com","authedmine.com","coinimp.com","browsermine"],
    "Spyware":       ["heatmap.me","spywarelabs","statcounter.com","histats.com","openstat.net","informer.com","trackcash.net","toplist.cz","cyberspy","remotespy"],
    "Social":        ["platform.twitter.com","connect.facebook.net","apis.google.com/js/platform","platform.linkedin.com","pinterest.com/ct"],
}

# ── Utility helpers ───────────────────────────────────────────────────────────
def get_domain(url):
    try: return urlparse(url).netloc.split(":")[0]
    except: return url

def get_ip(domain):
    try: return socket.gethostbyname(domain)
    except: return None

def safe_get(url, **kwargs):
    try:
        return http.get(url, headers=SESSION_HDR, timeout=TIMEOUT,
                        allow_redirects=True, verify=False, **kwargs)
    except: return None

def safe_post(url, **kwargs):
    try:
        return http.post(url, headers=SESSION_HDR, timeout=TIMEOUT,
                         allow_redirects=True, verify=False, **kwargs)
    except: return None

def emit(q, type_, **data):
    q.put({"type": type_, "ts": datetime.now().strftime("%H:%M:%S"), **data})

def finding(q, key, url="", evidence="", extra=None):
    f = FIXES.get(key, {"severity":"INFO","title":key,"fix":"Review manually.","ref":""})
    q.put({
        "type": "finding",
        "key": key, "severity": f["severity"],
        "title": f["title"], "url": url,
        "evidence": evidence[:300],
        "fix": f["fix"], "ref": f["ref"],
        **(extra or {})
    })

# ══════════════════════════════════════════════════════════════════════════════
#   SCANNER MODULES
# ══════════════════════════════════════════════════════════════════════════════

def scan_headers(base_url, q):
    emit(q, "progress", msg="Checking HTTP security headers...")
    r = safe_get(base_url)
    if not r:
        emit(q, "log", msg="Headers check failed — could not reach target", level="warn")
        return

    h = {k.lower(): v for k, v in r.headers.items()}

    checks = [
        ("strict-transport-security", "missing_hsts"),
        ("content-security-policy",   "missing_csp"),
        ("x-frame-options",           "missing_xfo"),
        ("x-content-type-options",    "missing_xcto"),
        ("referrer-policy",           "missing_rp"),
    ]
    for header, key in checks:
        if header not in h:
            finding(q, key, base_url, f"Header '{header}' not present in response")
        else:
            emit(q, "log", msg=f"✓ {header}: {h[header][:60]}", level="ok")

    if "server" in h:
        finding(q, "server_header", base_url, f"Server: {h['server']}")
    if "x-powered-by" in h:
        finding(q, "x_powered_by", base_url, f"X-Powered-By: {h['x-powered-by']}")

    # Cookie flags
    sc = r.headers.get("Set-Cookie","")
    if sc and not all(x in sc.lower() for x in ("secure","httponly","samesite")):
        finding(q, "missing_cookie_flags", base_url, f"Set-Cookie: {sc[:100]}")

    # CORS
    origin_test = {"Origin": "https://evil-attacker.com", **SESSION_HDR}
    rc = safe_get(base_url, headers=origin_test)
    if rc:
        acao = rc.headers.get("Access-Control-Allow-Origin","")
        if acao == "*":
            finding(q, "cors_wildcard", base_url, "Access-Control-Allow-Origin: *")
        elif "evil-attacker.com" in acao:
            finding(q, "cors_reflect", base_url,
                    f"Server reflected attacker origin: {acao}")


def scan_ssl(domain, q):
    emit(q, "progress", msg="Analysing SSL/TLS configuration...")
    try:
        ctx = ssl.create_default_context()
        conn = ctx.wrap_socket(socket.socket(), server_hostname=domain)
        conn.settimeout(10)
        conn.connect((domain, 443))
        cert = conn.getpeercert()
        conn.close()

        expire_str = cert.get("notAfter","")
        if expire_str:
            from datetime import datetime as dt
            exp = dt.strptime(expire_str, "%b %d %H:%M:%S %Y %Z")
            days_left = (exp - dt.utcnow()).days
            if days_left < 0:
                finding(q, "ssl_expired", f"https://{domain}",
                        f"Certificate expired {-days_left} days ago")
            elif days_left < 14:
                finding(q, "ssl_expired", f"https://{domain}",
                        f"Certificate expires in {days_left} days!")
            else:
                emit(q, "log", msg=f"✓ SSL valid — expires in {days_left} days", level="ok")
    except ssl.SSLError as e:
        finding(q, "ssl_weak", f"https://{domain}", str(e))
    except Exception as e:
        emit(q, "log", msg=f"SSL check error: {e}", level="warn")

    # SSL Labs API (no key needed)
    emit(q, "log", msg="Querying SSL Labs API (may take 60s)...", level="info")
    try:
        r = http.get("https://api.ssllabs.com/api/v3/analyze",
                     params={"host": domain, "fromCache": "on", "all": "done"},
                     timeout=90)
        data = r.json()
        grade = data.get("endpoints",[{}])[0].get("grade","?")
        emit(q, "metric", key="ssl_grade", value=grade,
             label="SSL Labs Grade",
             color="ok" if grade in ("A","A+") else "warn" if grade=="B" else "bad")
        if grade in ("F","T","M"):
            finding(q, "ssl_weak", f"https://{domain}",
                    f"SSL Labs grade: {grade}")
    except Exception as e:
        emit(q, "log", msg=f"SSL Labs unavailable: {e}", level="warn")


def scan_exposed_files(base_url, q):
    emit(q, "progress", msg="Scanning for exposed sensitive files...")
    PATHS = [
        ("/.git/HEAD",          "exposed_git",  "CRITICAL"),
        ("/.git/config",        "exposed_git",  "CRITICAL"),
        ("/.env",               "exposed_env",  "CRITICAL"),
        ("/.env.local",         "exposed_env",  "CRITICAL"),
        ("/.env.production",    "exposed_env",  "CRITICAL"),
        ("/config.php",         "exposed_env",  "CRITICAL"),
        ("/wp-config.php",      "exposed_env",  "CRITICAL"),
        ("/web.config",         "exposed_env",  "HIGH"),
        ("/phpinfo.php",        "server_header","HIGH"),
        ("/docker-compose.yml", "exposed_env",  "HIGH"),
        ("/Dockerfile",         "exposed_env",  "MEDIUM"),
        ("/.htaccess",          "exposed_env",  "MEDIUM"),
        ("/backup.zip",         "exposed_env",  "CRITICAL"),
        ("/backup.sql",         "exposed_env",  "CRITICAL"),
        ("/db.sql",             "exposed_env",  "CRITICAL"),
        ("/dump.sql",           "exposed_env",  "CRITICAL"),
        ("/robots.txt",         "dir_listing",  "INFO"),
        ("/sitemap.xml",        "dir_listing",  "INFO"),
    ]
    found_any = False
    for path, key, sev in PATHS:
        url = base_url.rstrip("/") + path
        r = safe_get(url)
        if r and r.status_code == 200 and len(r.text) > 10:
            snippet = r.text[:80].replace("\n"," ")
            finding(q, key, url, f"HTTP 200 — content: {snippet}")
            found_any = True

    if not found_any:
        emit(q, "log", msg="✓ No obvious sensitive files exposed", level="ok")


def scan_xss(base_url, q):
    emit(q, "progress", msg="Probing for reflected XSS...")
    PAYLOADS = [
        "<script>alert(1)</script>",
        '"><script>alert(1)</script>',
        "'><img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
        "javascript:alert(1)",
    ]
    parsed = urlparse(base_url)
    params = urllib.parse.parse_qs(parsed.query)
    test_params = list(params.keys()) or ["q", "search", "id", "page", "name", "input"]

    vuln = False
    for param in test_params[:5]:
        for payload in PAYLOADS:
            test_url = base_url.split("?")[0] + f"?{param}={urllib.parse.quote(payload)}"
            r = safe_get(test_url)
            if r and payload.lower() in r.text.lower():
                finding(q, "xss_reflected", test_url,
                        f"Payload reflected in response: {payload}")
                vuln = True
                break

    if not vuln:
        emit(q, "log", msg="✓ No obvious reflected XSS found in URL params", level="ok")


def scan_sqli(base_url, q):
    emit(q, "progress", msg="Probing for SQL injection...")
    DB_ERRORS = [
        "you have an error in your sql syntax",
        "warning: mysql","unclosed quotation mark",
        "microsoft sql server","psqlexception","sqlite3::",
        "ora-","syntax error","mysql_fetch","pg_query",
    ]
    PAYLOADS = ["'", "''", "' OR '1'='1", "' OR 1=1--", "'; SELECT 1--", '" OR "1"="1']
    parsed = urlparse(base_url)
    params = list(urllib.parse.parse_qs(parsed.query).keys()) or ["id","user","page","q","search"]

    vuln = False
    for param in params[:5]:
        for payload in PAYLOADS:
            test_url = base_url.split("?")[0] + f"?{param}={urllib.parse.quote(payload)}"
            r = safe_get(test_url)
            if r:
                body = r.text.lower()
                for err in DB_ERRORS:
                    if err in body:
                        finding(q, "sqli_error", test_url,
                                f"DB error triggered by payload: {payload} → {err}")
                        vuln = True
                        break

    if not vuln:
        emit(q, "log", msg="✓ No obvious SQL injection errors triggered", level="ok")


def scan_open_redirect(base_url, q):
    emit(q, "progress", msg="Testing for open redirects...")
    TARGET = "https://evil-attacker-test.com"
    PARAMS = ["redirect","url","next","return","goto","redir","destination",
              "link","location","continue","target","out","view","to","ref"]
    base = base_url.split("?")[0]
    vuln = False
    for param in PARAMS:
        test_url = f"{base}?{param}={urllib.parse.quote(TARGET)}"
        try:
            r = http.get(test_url, headers=SESSION_HDR, timeout=TIMEOUT,
                         allow_redirects=False, verify=False)
            loc = r.headers.get("Location","")
            if TARGET in loc or "evil-attacker-test" in loc:
                finding(q, "open_redirect", test_url,
                        f"Redirects to: {loc}")
                vuln = True
        except: pass

    if not vuln:
        emit(q, "log", msg="✓ No open redirect in common params", level="ok")


def scan_trackers(base_url, q):
    emit(q, "progress", msg="Scanning for trackers, spyware, and cryptominers...")
    r = safe_get(base_url)
    if not r:
        return

    body = r.text.lower()
    found_categories = {}

    for category, domains in TRACKERS.items():
        hits = [d for d in domains if d.lower() in body]
        if hits:
            found_categories[category] = hits

    if found_categories:
        for cat, hits in found_categories.items():
            key = "cryptominer" if cat == "Cryptominer" else \
                  "tracker_found" if cat in ("Analytics","Advertising","Social") else \
                  "cryptominer" if cat == "Spyware" else "tracker_found"
            finding(q, key, base_url,
                    f"[{cat}] Found: {', '.join(hits[:5])}")
    else:
        emit(q, "log", msg="✓ No known trackers or miners detected", level="ok")

    # Check for suspicious external scripts
    scripts = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', r.text, re.I)
    ext = [s for s in scripts if urlparse(s).netloc and
           urlparse(s).netloc not in get_domain(base_url)]
    if ext:
        emit(q, "log",
             msg=f"External scripts loaded: {len(ext)} ({', '.join(ext[:3])})",
             level="warn")


def scan_reputation(url, domain, ip, q):
    emit(q, "progress", msg="Checking reputation databases...")

    # ── VirusTotal ────────────────────────────────────────────────────────────
    if KEYS["virustotal"]:
        emit(q, "log", msg="Querying VirusTotal...", level="info")
        try:
            url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
            r = http.get(f"https://www.virustotal.com/api/v3/urls/{url_id}",
                         headers={"x-apikey": KEYS["virustotal"]}, timeout=20)
            if r.status_code == 200:
                stats = r.json()["data"]["attributes"]["last_analysis_stats"]
                malicious = stats.get("malicious", 0)
                suspicious = stats.get("suspicious", 0)
                total = sum(stats.values())
                emit(q, "metric", key="vt", label="VirusTotal",
                     value=f"{malicious}/{total} engines flagged",
                     color="bad" if malicious > 0 else "ok")
                if malicious > 0:
                    finding(q, "phishing", url,
                            f"VirusTotal: {malicious} engines flagged as malicious")
            elif r.status_code == 404:
                emit(q, "log", msg="VirusTotal: URL not yet in database", level="info")
        except Exception as e:
            emit(q, "log", msg=f"VirusTotal error: {e}", level="warn")
    else:
        emit(q, "log", msg="VirusTotal: no API key set (skipped)", level="info")

    # ── URLScan.io ────────────────────────────────────────────────────────────
    if KEYS["urlscan"]:
        emit(q, "log", msg="Submitting to URLScan.io...", level="info")
        try:
            r = http.post("https://urlscan.io/api/v1/scan/",
                          headers={"API-Key": KEYS["urlscan"],
                                   "Content-Type": "application/json"},
                          json={"url": url, "visibility": "unlisted"}, timeout=20)
            if r.status_code == 200:
                uuid = r.json().get("uuid","")
                emit(q, "log",
                     msg=f"URLScan submitted — result: https://urlscan.io/result/{uuid}/",
                     level="info")
                time.sleep(12)
                rs = http.get(f"https://urlscan.io/api/v1/result/{uuid}/",
                              timeout=30)
                if rs.status_code == 200:
                    data = rs.json()
                    verdict = data.get("verdicts",{}).get("overall",{})
                    score   = verdict.get("score", 0)
                    mal     = verdict.get("malicious", False)
                    emit(q, "metric", key="urlscan", label="URLScan Score",
                         value=str(score), color="bad" if mal else "ok")
                    if mal:
                        finding(q, "phishing", url,
                                f"URLScan verdict: MALICIOUS (score {score})")
        except Exception as e:
            emit(q, "log", msg=f"URLScan error: {e}", level="warn")
    else:
        emit(q, "log", msg="URLScan: no API key set — using search cache...", level="info")
        try:
            r = http.get(f"https://urlscan.io/api/v1/search/?q=domain:{domain}&size=1",
                         timeout=15)
            if r.status_code == 200:
                hits = r.json().get("results", [])
                if hits:
                    score = hits[0].get("verdicts",{}).get("overall",{}).get("score",0)
                    emit(q, "log",
                         msg=f"URLScan cached result — score: {score}", level="info")
        except: pass

    # ── AbuseIPDB ─────────────────────────────────────────────────────────────
    if ip and KEYS["abuseipdb"]:
        emit(q, "log", msg="Checking AbuseIPDB...", level="info")
        try:
            r = http.get("https://api.abuseipdb.com/api/v2/check",
                         headers={"Key": KEYS["abuseipdb"], "Accept": "application/json"},
                         params={"ipAddress": ip, "maxAgeInDays": "90"}, timeout=15)
            if r.status_code == 200:
                d = r.json()["data"]
                score = d.get("abuseConfidenceScore", 0)
                emit(q, "metric", key="abuse", label="AbuseIPDB Score",
                     value=f"{score}%", color="bad" if score>50 else "warn" if score>10 else "ok")
                if score > 25:
                    finding(q, "ip_abuse", url,
                            f"IP {ip} abuse confidence: {score}%  ({d.get('totalReports',0)} reports)")
        except Exception as e:
            emit(q, "log", msg=f"AbuseIPDB error: {e}", level="warn")
    else:
        emit(q, "log", msg="AbuseIPDB: no API key set (skipped)", level="info")

    # ── Google Safe Browsing ──────────────────────────────────────────────────
    if KEYS["google_safe"]:
        emit(q, "log", msg="Checking Google Safe Browsing...", level="info")
        try:
            r = http.post(
                f"https://safebrowsing.googleapis.com/v4/threatMatches:find"
                f"?key={KEYS['google_safe']}",
                json={
                    "client": {"clientId": "cyberlab", "clientVersion": "2.0"},
                    "threatInfo": {
                        "threatTypes": ["MALWARE","SOCIAL_ENGINEERING","UNWANTED_SOFTWARE","POTENTIALLY_HARMFUL_APPLICATION"],
                        "platformTypes": ["ANY_PLATFORM"],
                        "threatEntryTypes": ["URL"],
                        "threatEntries": [{"url": url}]
                    }
                }, timeout=15)
            if r.status_code == 200:
                matches = r.json().get("matches", [])
                if matches:
                    t = matches[0].get("threatType","UNKNOWN")
                    finding(q, "phishing", url,
                            f"Google Safe Browsing: {t}")
                else:
                    emit(q, "log", msg="✓ Google Safe Browsing: CLEAN", level="ok")
        except Exception as e:
            emit(q, "log", msg=f"Google Safe Browsing error: {e}", level="warn")

    # ── PhishTank (no key needed) ─────────────────────────────────────────────
    emit(q, "log", msg="Checking PhishTank...", level="info")
    try:
        r = http.post("https://checkurl.phishtank.com/checkurl/",
                      data={"url": urllib.parse.quote(url), "format": "json"},
                      timeout=15, headers={"User-Agent": UA})
        if r.status_code == 200:
            d = r.json().get("results",{})
            if d.get("in_database") and d.get("valid"):
                finding(q, "phishing", url, "Listed in PhishTank phishing database")
            else:
                emit(q, "log", msg="✓ PhishTank: not in database", level="ok")
    except Exception as e:
        emit(q, "log", msg=f"PhishTank error: {e}", level="warn")


def scan_recon(url, domain, ip, q):
    emit(q, "progress", msg="Running reconnaissance...")

    # DNS
    emit(q, "log", msg=f"Domain: {domain}", level="info")
    emit(q, "log", msg=f"IP:     {ip or 'unresolved'}", level="info")

    # HTTP response info
    r = safe_get(url)
    if r:
        emit(q, "log", msg=f"HTTP Status: {r.status_code}", level="info")
        emit(q, "log", msg=f"Final URL:   {r.url}", level="info")
        content_len = len(r.content)
        emit(q, "log", msg=f"Response size: {content_len} bytes", level="info")
        title_m = re.search(r"<title[^>]*>([^<]+)</title>", r.text, re.I)
        if title_m:
            emit(q, "log", msg=f"Page title: {title_m.group(1).strip()[:60]}", level="info")

    # Whois (via API — no key needed)
    try:
        wr = http.get(f"https://api.whois.vu/?q={domain}", timeout=10)
        if wr.status_code == 200:
            wdata = wr.json()
            reg = wdata.get("registrar","?")
            created = wdata.get("creation_date","?")
            emit(q, "log", msg=f"Registrar: {reg} | Created: {created}", level="info")
    except: pass

    # Shodan
    if ip and KEYS["shodan"]:
        try:
            sr = http.get(f"https://api.shodan.io/shodan/host/{ip}",
                          params={"key": KEYS["shodan"]}, timeout=15)
            if sr.status_code == 200:
                sd = sr.json()
                ports = sd.get("ports", [])
                emit(q, "log", msg=f"Shodan open ports: {ports}", level="info")
                emit(q, "metric", key="ports", label="Open Ports",
                     value=str(len(ports)), color="warn" if len(ports)>5 else "ok")
        except: pass
    elif ip:
        # Fallback: basic port probe on common ports
        COMMON = [21,22,23,25,80,443,3306,5432,6379,8080,8443,27017]
        open_ports = []
        for port in COMMON:
            try:
                s = socket.socket()
                s.settimeout(1)
                if s.connect_ex((ip, port)) == 0:
                    open_ports.append(port)
                s.close()
            except: pass
        if open_ports:
            emit(q, "log", msg=f"Open ports detected: {open_ports}", level="warn")
            emit(q, "metric", key="ports", label="Open Ports",
                 value=str(len(open_ports)), color="warn" if len(open_ports)>3 else "ok")


# ══════════════════════════════════════════════════════════════════════════════
#   FLASK ROUTES
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/keys", methods=["GET","POST"])
def handle_keys():
    global KEYS
    if request.method == "GET":
        # Reload from .env so the response always reflects the file on disk
        KEYS = _load_keys()
        active = [k for k,v in KEYS.items() if v]
        return jsonify({
            "ok":         True,
            "active":     active,
            "env_file":   str(ENV_FILE),
            "env_exists": ENV_FILE.exists(),
        })

    # POST — save new/updated keys to .env then reload
    data = request.json or {}
    _write_env(data)
    KEYS = _load_keys()          # refresh module-level cache immediately
    active = [k for k,v in KEYS.items() if v]
    return jsonify({
        "ok":         True,
        "active":     active,
        "env_file":   str(ENV_FILE),
        "saved":      True,
    })


@app.route("/api/scan")
def scan():
    url     = request.args.get("url","").strip()
    modules = request.args.get("modules","all")

    if not url:
        return jsonify({"error": "No URL provided"}), 400
    if not url.startswith(("http://","https://")):
        url = "https://" + url

    # Reload keys from .env on every scan — picks up edits without restart
    global KEYS
    KEYS = _load_keys()

    mods = set(modules.split(",")) if modules != "all" else \
           {"recon","headers","ssl","files","xss","sqli","redirect","trackers","reputation"}

    def generate():
        q = queue.Queue()

        def run():
            try:
                domain = get_domain(url)
                ip     = get_ip(domain)

                emit(q, "start", url=url, domain=domain, ip=ip or "?",
                     ts=datetime.now().isoformat())

                with ThreadPoolExecutor(max_workers=4) as ex:
                    futures = []
                    if "recon"      in mods: futures.append(ex.submit(scan_recon,      url, domain, ip, q))
                    if "headers"    in mods: futures.append(ex.submit(scan_headers,    url, q))
                    if "ssl"        in mods: futures.append(ex.submit(scan_ssl,        domain, q))
                    if "files"      in mods: futures.append(ex.submit(scan_exposed_files, url, q))
                    if "xss"        in mods: futures.append(ex.submit(scan_xss,        url, q))
                    if "sqli"       in mods: futures.append(ex.submit(scan_sqli,       url, q))
                    if "redirect"   in mods: futures.append(ex.submit(scan_open_redirect, url, q))
                    if "trackers"   in mods: futures.append(ex.submit(scan_trackers,   url, q))
                    if "reputation" in mods: futures.append(ex.submit(scan_reputation, url, domain, ip, q))
                    for f in as_completed(futures): f.result()

            except Exception as e:
                emit(q, "log", msg=f"Scan error: {e}", level="error")
            finally:
                emit(q, "done")

        t = threading.Thread(target=run, daemon=True)
        t.start()

        while True:
            try:
                item = q.get(timeout=120)
                yield f"data: {json.dumps(item)}\n\n"
                if item.get("type") == "done":
                    break
            except queue.Empty:
                yield "data: {\"type\":\"done\"}\n\n"
                break

    return Response(
        stream_with_context(generate()),
        content_type="text/event-stream",
        headers={"Cache-Control":"no-cache","X-Accel-Buffering":"no"}
    )


@app.route("/api/report", methods=["POST"])
def report():
    data = request.json or {}
    findings = data.get("findings", [])
    meta     = data.get("meta", {})

    sev_order = {"CRITICAL":0,"HIGH":1,"MEDIUM":2,"LOW":3,"INFO":4}
    findings.sort(key=lambda f: sev_order.get(f.get("severity","INFO"),4))

    score = 100
    for f in findings:
        s = f.get("severity","INFO")
        score -= {"CRITICAL":25,"HIGH":15,"MEDIUM":8,"LOW":3,"INFO":0}.get(s,0)
    score = max(0, score)

    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    html = f"""<!DOCTYPE html>
<html><head><meta charset="UTF-8">
<title>CyberLab Report — {meta.get('url','')}</title>
<style>
*{{margin:0;padding:0;box-sizing:border-box}}
body{{background:#0a0a0f;color:#c0c0c0;font-family:'Courier New',monospace;padding:30px}}
h1{{color:#00ff41;font-size:2em;border-bottom:1px solid #00ff41;padding-bottom:10px;margin-bottom:20px}}
h2{{color:#00d4ff;margin:20px 0 10px}}
.meta{{color:#888;font-size:.9em;margin-bottom:20px}}
.score{{font-size:3em;font-weight:bold;color:{'#00ff41' if score>=70 else '#ff9500' if score>=40 else '#ff003c'}}}
.finding{{border:1px solid #333;border-radius:4px;padding:15px;margin:10px 0;border-left:4px solid #888}}
.CRITICAL{{border-left-color:#ff003c}} .HIGH{{border-left-color:#ff4500}}
.MEDIUM{{border-left-color:#ffaa00}} .LOW{{border-left-color:#00aaff}}
.sev{{display:inline-block;padding:2px 8px;border-radius:3px;font-size:.8em;font-weight:bold;
      margin-right:8px;color:#000}}
.CRITICAL .sev{{background:#ff003c}} .HIGH .sev{{background:#ff4500}}
.MEDIUM .sev{{background:#ffaa00}} .LOW .sev{{background:#00aaff;color:#000}}
.fix{{background:#0d1f0d;padding:10px;margin-top:8px;border-radius:3px;font-size:.85em}}
.ev{{color:#888;font-size:.85em;margin-top:6px;word-break:break-all}}
a{{color:#00d4ff}}
</style></head><body>
<h1>⚡ CyberLab Security Report</h1>
<div class="meta">Target: <b style="color:#00d4ff">{meta.get('url','')}</b> &nbsp;|&nbsp;
Scanned: {now} &nbsp;|&nbsp; IP: {meta.get('ip','?')} &nbsp;|&nbsp; Domain: {meta.get('domain','?')}</div>
<h2>Security Score</h2>
<div class="score">{score}/100</div>
<p style="color:#888;margin:5px 0 20px">{'SECURE' if score>=80 else 'MODERATE RISK' if score>=50 else 'HIGH RISK'}</p>
<h2>Findings ({len(findings)})</h2>"""

    for f in findings:
        sev = f.get("severity","INFO")
        html += f"""
<div class="finding {sev}">
  <span class="sev">{sev}</span> <b>{f.get('title','')}</b>
  <div class="ev">Evidence: {f.get('evidence','')}</div>
  <div class="ev">URL: <a href="{f.get('url','')}">{f.get('url','')}</a></div>
  <div class="fix">🔧 Fix: {f.get('fix','')}
  {'<br>📎 <a href="' + f.get('ref','') + '">' + f.get('ref','') + '</a>' if f.get('ref') else ''}</div>
</div>"""

    html += f"""
<h2>Summary by Severity</h2>
<table style="border-collapse:collapse;width:100%">
<tr style="color:#00d4ff"><th>Severity</th><th>Count</th></tr>"""
    for sev in ["CRITICAL","HIGH","MEDIUM","LOW","INFO"]:
        cnt = sum(1 for f in findings if f.get("severity")==sev)
        if cnt:
            html += f"<tr><td style='padding:4px 8px'>{sev}</td><td>{cnt}</td></tr>"
    html += f"</table><p style='color:#555;margin-top:30px;font-size:.8em'>Generated by CyberLab v2.0 — {now}</p></body></html>"

    return jsonify({"html": html, "score": score})


if __name__ == "__main__":
    import urllib3
    urllib3.disable_warnings()
    print("\n⚡ CyberLab starting on http://0.0.0.0:5050")
    app.run(host="0.0.0.0", port=5050, debug=False, threaded=True)
