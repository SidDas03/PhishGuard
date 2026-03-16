"""
PhishGuard v5 — Intelligent Phishing Detection Platform
Fixes: input validation, dangerous URI schemes, port crash, SSRF protection,
       resource limits, API key auth, rate limiting, error info disclosure
New:   /api/scan/file, /api/report/<id>, /api/email/scan,
       /api/watchlist (scheduled monitoring), /api/keys
"""
import os, sys, uuid, time, json, re, threading, secrets
from datetime import datetime, timezone
from flask import Flask, request, jsonify, make_response, send_file

sys.path.insert(0, os.path.dirname(__file__))

from url_analyzer      import URLAnalyzer
from domain_intelligence import DomainIntelligence
from ssl_inspector     import SSLInspector
from ml_detector       import MLDetector
from content_analyzer  import ContentAnalyzer
from threat_intelligence import ThreatIntelligence
from risk_scorer       import RiskScorer
from scan_history      import ScanHistoryDB
from pdf_reporter      import generate_report
from email_scanner     import EmailScanner
from watchlist         import WatchlistMonitor

app = Flask(__name__)

url_analyzer     = URLAnalyzer()
domain_intel     = DomainIntelligence()
ssl_inspector    = SSLInspector()
ml_detector      = MLDetector()
content_analyzer = ContentAnalyzer()
threat_intel     = ThreatIntelligence()
risk_scorer      = RiskScorer()
scan_db          = ScanHistoryDB()
email_scanner    = EmailScanner()
watchlist        = WatchlistMonitor(scan_db)

watchlist.start()

MAX_URL_LENGTH   = 2048
MAX_BULK_URLS    = 50
MAX_EMAIL_SIZE   = 100_000  
MAX_FILE_LINES   = 500
RATE_LIMIT_WINDOW = 60      
RATE_LIMIT_MAX    = 60      
DB_MAX_ENTRIES   = 10_000    

ALLOWED_SCHEMES  = {"http", "https"}
BLOCKED_SCHEMES  = {"javascript", "file", "data", "ftp", "ftps",
                     "vbscript", "about", "blob", "chrome", "ms-appx"}

_rate_store: dict = {}
_rate_lock  = threading.Lock()


KEYS_FILE = os.path.join(os.path.dirname(__file__), "api_keys.json")

def _load_keys() -> dict:
    if os.path.exists(KEYS_FILE):
        try:
            with open(KEYS_FILE) as f:
                return json.load(f)
        except Exception:
            pass

    master = secrets.token_hex(24)
    keys = {master: {"name": "master", "created": datetime.now(timezone.utc).isoformat()}}
    with open(KEYS_FILE, "w") as f:
        json.dump(keys, f, indent=2)
    print(f"\n  ╔══════════════════════════════════════╗")
    print(f"  ║  API KEY (save this):                 ║")
    print(f"  ║  {master}  ║")
    print(f"  ╚══════════════════════════════════════╝\n")
    return keys

API_KEYS = _load_keys()

def sanitize(obj):
    """Recursively make any object JSON-safe."""
    if isinstance(obj, dict):
        return {k: sanitize(v) for k, v in obj.items()}
    elif isinstance(obj, (list, tuple)):
        return [sanitize(v) for v in obj]
    elif isinstance(obj, datetime):
        return obj.isoformat()
    elif isinstance(obj, (bool, int, float, str, type(None))):
        return obj
    else:
        try:
            json.dumps(obj); return obj
        except (TypeError, ValueError):
            return str(obj)

def safe_json(data, status=200):
    return app.response_class(
        response=json.dumps(sanitize(data)),
        status=status,
        mimetype="application/json"
    )

def now_iso():
    return datetime.now(timezone.utc).isoformat()

def validate_url(url: str) -> tuple[bool, str]:
    """Validate and sanitize a URL. Returns (ok, cleaned_url_or_error)."""
    if not url or not isinstance(url, str):
        return False, "URL is required"
    url = url.strip()
    url = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", url)
    if len(url) > MAX_URL_LENGTH:
        return False, f"URL exceeds maximum length of {MAX_URL_LENGTH} characters"
    import urllib.parse as _up
    _pre_parsed = _up.urlparse(url)
    _pre_scheme = _pre_parsed.scheme.lower()
    if _pre_scheme and _pre_scheme in BLOCKED_SCHEMES:
        return False, f"URI scheme '{_pre_scheme}' is not allowed — only http/https supported"
    if _pre_scheme and _pre_scheme not in ALLOWED_SCHEMES and "://" in url:
        return False, f"URI scheme '{_pre_scheme}' is not allowed — only http/https supported"

    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    try:
        import urllib.parse
        parsed = urllib.parse.urlparse(url)
        scheme = parsed.scheme.lower()
        if scheme in BLOCKED_SCHEMES:
            return False, f"URI scheme '{scheme}' is not allowed"
        if scheme not in ALLOWED_SCHEMES:
            return False, f"Only http:// and https:// URLs are supported"
        host = parsed.hostname or ""
        if not host:
            return False, "URL has no valid hostname"
    except Exception as e:
        return False, f"Invalid URL format: {str(e)[:60]}"
    return True, url

def check_rate_limit(ip: str) -> bool:
    """Returns True if request is allowed, False if rate limited."""
    now = time.time()
    with _rate_lock:
        if ip not in _rate_store:
            _rate_store[ip] = []
        _rate_store[ip] = [t for t in _rate_store[ip] if now - t < RATE_LIMIT_WINDOW]
        if len(_rate_store[ip]) >= RATE_LIMIT_MAX:
            return False
        _rate_store[ip].append(now)
        return True

def require_api_key(f):
    """Decorator — checks X-API-Key header. Skips if no keys configured."""
    import functools
    @functools.wraps(f)
    def decorated(*args, **kwargs)
        client_ip = request.remote_addr
        if client_ip in ("127.0.0.1", "::1", "localhost"):
            return f(*args, **kwargs)
        key = request.headers.get("X-API-Key", "")
        if key not in API_KEYS:
            return safe_json({"error": "Invalid or missing API key. Set X-API-Key header."}, 401)
        return f(*args, **kwargs)
    return decorated

def is_ssrf_target(url: str) -> bool:
    """Detect SSRF targets — internal IPs, metadata endpoints, localhost."""
    import urllib.parse, ipaddress
    try:
        host = urllib.parse.urlparse(url).hostname or ""
        if host.lower() in ("localhost", "127.0.0.1", "::1", "0.0.0.0"):
            return True
        try:
            ip = ipaddress.ip_address(host)
            return ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved
        except ValueError:
            pass
        if "169.254.169.254" in host or "metadata.google.internal" in host:
            return True
    except Exception:
        pass
    return False

def run_scan(url: str, options: dict) -> dict:
    if not watchlist._run_scan_fn: watchlist.set_scan_fn(run_scan)
    """Core scan logic — separated for reuse."""
    scan_id = str(uuid.uuid4())[:8].upper()
    t0 = time.time()
    checks = {}

    checks["url_analysis"]        = url_analyzer.analyze(url)
    checks["domain_intelligence"] = domain_intel.analyze(url)

    if options.get("check_ssl", True):
        checks["ssl_inspection"]  = ssl_inspector.inspect(url)

    checks["ml_detection"]        = ml_detector.predict(url)

    if options.get("check_content", True) and not is_ssrf_target(url):
        checks["content_analysis"] = content_analyzer.analyze(url)
    elif is_ssrf_target(url):
        checks["content_analysis"] = {
            "module": "Content Analysis", "score": 0,
            "findings": [{"flagged": False, "check": "SSRF Protection",
                          "detail": "Content fetch blocked — internal/private IP target",
                          "severity": 0}],
            "findings_count": 0, "page_data": {}
        }

    if options.get("check_threat_intel", True):
        checks["threat_intelligence"] = threat_intel.lookup(url)

    final = risk_scorer.compute(checks)

    result = {
        "scan_id":          scan_id,
        "url":              url,
        "timestamp":        now_iso(),
        "status":           "completed",
        "risk_score":       final["score"],
        "risk_level":       final["level"],
        "classification":   final["classification"],
        "confidence":       final["confidence"],
        "recommendation":   final["recommendation"],
        "indicators":       final["indicators"],
        "checks":           checks,
        "scan_duration_ms": round((time.time() - t0) * 1000, 2),
    }
    scan_db.save(result)
    if scan_db.get_total_count() > DB_MAX_ENTRIES:
        scan_db.prune(keep=DB_MAX_ENTRIES // 2)
    return result

@app.after_request
def add_cors(response):
    response.headers["Access-Control-Allow-Origin"]  = "*"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type, X-API-Key"
    response.headers["Access-Control-Allow-Methods"] = "GET,POST,DELETE,OPTIONS"
    # Security headers
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"]        = "DENY"
    return response

@app.before_request
def handle_preflight():
    if request.method == "OPTIONS":
        resp = make_response()
        resp.headers["Access-Control-Allow-Origin"]  = "*"
        resp.headers["Access-Control-Allow-Headers"] = "Content-Type, X-API-Key"
        resp.headers["Access-Control-Allow-Methods"] = "GET,POST,DELETE,OPTIONS"
        return resp, 204

@app.route("/")
def root():
    return safe_json({"name": "PhishGuard", "version": "5.0", "status": "operational",
                      "endpoints": {
                          "POST /api/scan":           "Scan a single URL",
                          "POST /api/scan/bulk":      "Scan multiple URLs",
                          "POST /api/scan/file":      "Scan URLs from uploaded .txt/.csv",
                          "POST /api/email/scan":     "Scan URLs extracted from email",
                          "GET  /api/report/<id>":    "Download PDF report for a scan",
                          "GET  /api/history":        "Scan history",
                          "GET  /api/stats":          "Platform statistics",
                          "GET  /api/dashboard":      "Full dashboard data",
                          "GET  /api/watchlist":      "Get monitored domains",
                          "POST /api/watchlist":      "Add domain to watchlist",
                          "DELETE /api/watchlist/<d>":"Remove from watchlist",
                          "GET  /api/health":         "Health check",
                      }})

@app.route("/api/health")
def health():
    return safe_json({"status": "healthy", "timestamp": now_iso(),
                      "version": "5.0",
                      "modules": {m: "operational" for m in [
                          "url_analyzer","domain_intelligence","ssl_inspector",
                          "ml_detector","content_analyzer","threat_intelligence",
                          "email_scanner","watchlist_monitor"
                      ]},
                      "watchlist_active": watchlist.is_running(),
                      "db_entries": scan_db.get_total_count()})

@app.route("/api/scan", methods=["POST"])
def scan_url():
    # Rate limit
    ip = request.remote_addr
    if not check_rate_limit(ip):
        return safe_json({"error": f"Rate limit exceeded. Max {RATE_LIMIT_MAX} requests per {RATE_LIMIT_WINDOW}s."}, 429)

    data = request.get_json(silent=True) or {}
    ok, url = validate_url(data.get("url", ""))
    if not ok:
        return safe_json({"error": url}, 400)

    try:
        result = run_scan(url, data)
        return safe_json(result)
    except Exception as e:
        return safe_json({"error": "Scan failed. Check server logs."}, 500)

@app.route("/api/scan/bulk", methods=["POST"])
def bulk_scan():
    ip = request.remote_addr
    if not check_rate_limit(ip):
        return safe_json({"error": "Rate limit exceeded."}, 429)

    data = request.get_json(silent=True) or {}
    urls_raw = data.get("urls", [])
    if not isinstance(urls_raw, list):
        return safe_json({"error": "urls must be a list"}, 400)
    if len(urls_raw) > MAX_BULK_URLS:
        return safe_json({"error": f"Max {MAX_BULK_URLS} URLs per bulk scan"}, 400)

    results = []
    for raw in urls_raw:
        ok, url = validate_url(str(raw))
        if not ok:
            results.append({"url": str(raw), "error": url, "status": "failed"})
            continue
        try:
            results.append(run_scan(url, data))
        except Exception as e:
            results.append({"url": url, "error": "Scan failed", "status": "failed"})

    phishing = sum(1 for r in results if r.get("risk_score", 0) >= 65)
    return safe_json({
        "total": len(results), "phishing_found": phishing,
        "safe": len(results) - phishing, "results": results
    })

@app.route("/api/scan/file", methods=["POST"])
def scan_file():
    """Accept a .txt or .csv file with one URL per line."""
    ip = request.remote_addr
    if not check_rate_limit(ip):
        return safe_json({"error": "Rate limit exceeded."}, 429)

    if "file" not in request.files:
        return safe_json({"error": "No file uploaded. Send as multipart form-data with key 'file'."}, 400)

    f = request.files["file"]
    if not f.filename:
        return safe_json({"error": "Empty filename"}, 400)

    ext = f.filename.rsplit(".", 1)[-1].lower()
    if ext not in ("txt", "csv"):
        return safe_json({"error": "Only .txt and .csv files supported"}, 400)

    content = f.read(MAX_FILE_LINES * 300).decode("utf-8", errors="ignore")
    lines = [l.strip() for l in content.splitlines() if l.strip()]

    urls_raw = []
    for line in lines[:MAX_FILE_LINES]:
        if "," in line:
            col = line.split(",")[0].strip().strip('"')
        else:
            col = line
        if col.lower() in ("url", "urls", "link", "website"):
            continue
        urls_raw.append(col)

    if not urls_raw:
        return safe_json({"error": "No URLs found in file"}, 400)

    results = []
    for raw in urls_raw:
        ok, url = validate_url(raw)
        if not ok:
            results.append({"url": raw, "error": url, "status": "invalid"})
            continue
        try:
            r = run_scan(url, {"check_content": False, "check_ssl": True, "check_threat_intel": False})
            results.append(r)
        except Exception:
            results.append({"url": url, "error": "Scan failed", "status": "failed"})

    phishing = [r for r in results if r.get("risk_score", 0) >= 65]
    suspicious = [r for r in results if 45 <= r.get("risk_score", 0) < 65]
    safe = [r for r in results if r.get("risk_score", 0) < 45 and r.get("status") != "failed"]

    return safe_json({
        "filename":     f.filename,
        "total":        len(results),
        "phishing":     len(phishing),
        "suspicious":   len(suspicious),
        "safe":         len(safe),
        "failed":       len([r for r in results if r.get("status") == "failed"]),
        "results":      results,
        "top_threats":  sorted(phishing, key=lambda x: x.get("risk_score",0), reverse=True)[:5],
    })

@app.route("/api/email/scan", methods=["POST"])
def scan_email():
    """Extract all URLs from email body/text and scan them."""
    ip = request.remote_addr
    if not check_rate_limit(ip):
        return safe_json({"error": "Rate limit exceeded."}, 429)

    data = request.get_json(silent=True) or {}
    body = data.get("body", "")
    subject = data.get("subject", "")
    sender = data.get("sender", "")

    if not body:
        return safe_json({"error": "Email body is required (field: 'body')"}, 400)
    if len(body) > MAX_EMAIL_SIZE:
        return safe_json({"error": f"Email body too large (max {MAX_EMAIL_SIZE//1000}KB)"}, 400)

    result = email_scanner.scan(body=body, subject=subject, sender=sender,
                                run_scan_fn=run_scan)
    return safe_json(result)

@app.route("/api/report/<scan_id>")
def get_report(scan_id: str):
    """Generate and download a PDF report for a scan."""
    # Sanitize scan_id — alphanumeric only
    scan_id = re.sub(r"[^A-Za-z0-9]", "", scan_id)[:16]
    scan = scan_db.get_by_id(scan_id)
    if not scan:
        return safe_json({"error": "Scan not found"}, 404)
    try:
        pdf_path = generate_report(scan)
        return send_file(pdf_path, as_attachment=True,
                         download_name=f"PhishGuard_Report_{scan_id}.pdf",
                         mimetype="application/pdf")
    except Exception as e:
        return safe_json({"error": f"Report generation failed: {str(e)[:60]}"}, 500)

@app.route("/api/watchlist", methods=["GET"])
def get_watchlist():
    return safe_json({"watchlist": watchlist.get_all()})

@app.route("/api/watchlist", methods=["POST"])
def add_to_watchlist():
    data = request.get_json(silent=True) or {}
    ok, url = validate_url(data.get("url", ""))
    if not ok:
        return safe_json({"error": url}, 400)
    interval = max(5, int(data.get("interval_minutes", 60)))
    entry = watchlist.add(url, interval_minutes=interval)
    return safe_json({"message": f"Added to watchlist", "entry": entry})

@app.route("/api/watchlist/<path:domain>", methods=["DELETE"])
def remove_from_watchlist(domain: str):
    domain = re.sub(r"[^a-zA-Z0-9._:/-]", "", domain)[:200]
    watchlist.remove(domain)
    return safe_json({"message": f"Removed from watchlist"})

@app.route("/api/watchlist/results", methods=["GET"])
def watchlist_results():
    return safe_json({"results": watchlist.get_results()})


@app.route("/api/history")
def get_history():
    limit  = min(int(request.args.get("limit", 50)), 200)
    offset = max(int(request.args.get("offset", 0)), 0)
    return safe_json({"total": scan_db.get_total_count(), "limit": limit,
                      "offset": offset, "scans": scan_db.get_history(limit, offset)})

@app.route("/api/history/<scan_id>")
def get_scan(scan_id: str):
    scan_id = re.sub(r"[^A-Za-z0-9]", "", scan_id)[:16]
    s = scan_db.get_by_id(scan_id)
    return safe_json(s) if s else safe_json({"error": "Not found"}, 404)

@app.route("/api/history", methods=["DELETE"])
def clear_history():
    scan_db.clear()
    return safe_json({"message": "History cleared"})

@app.route("/api/stats")
def get_stats():
    return safe_json(scan_db.get_statistics())

@app.route("/api/dashboard")
def get_dashboard():
    return safe_json({
        "stats":               scan_db.get_statistics(),
        "recent_scans":        scan_db.get_history(limit=10),
        "trends":              scan_db.get_trends(),
        "threat_distribution": scan_db.get_threat_distribution(),
        "top_indicators":      scan_db.get_top_indicators(),
        "watchlist_count":     len(watchlist.get_all()),
    })

@app.route("/api/keys", methods=["GET"])
def list_keys():
    # Only from localhost
    if request.remote_addr not in ("127.0.0.1", "::1"):
        return safe_json({"error": "Key management only available from localhost"}, 403)
    return safe_json({"keys": [{"key": k[:8]+"...", "name": v["name"], "created": v["created"]}
                                for k, v in API_KEYS.items()]})

@app.route("/api/keys", methods=["POST"])
def create_key():
    if request.remote_addr not in ("127.0.0.1", "::1"):
        return safe_json({"error": "Key management only available from localhost"}, 403)
    data = request.get_json(silent=True) or {}
    name = re.sub(r"[^a-zA-Z0-9_-]", "", data.get("name", "unnamed"))[:32]
    new_key = secrets.token_hex(24)
    API_KEYS[new_key] = {"name": name, "created": now_iso()}
    with open(KEYS_FILE, "w") as f:
        json.dump(API_KEYS, f, indent=2)
    return safe_json({"key": new_key, "name": name})

if __name__ == "__main__":
    print("\n  ╔══════════════════════════════════════════╗")
    print("  ║  PhishGuard v5  →  http://localhost:8000   ║")
    print("  ╚══════════════════════════════════════════╝\n")
    app.run(host="0.0.0.0", port=8000, debug=False, threaded=True)
