"""
Scan History Database - SQLite-based persistence for scan results
"""

import sqlite3
import json
import os
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional


def _sanitize_for_json(obj):
    """Recursively convert any non-JSON-serializable objects to safe types."""
    from datetime import datetime, date
    if isinstance(obj, dict):
        return {k: _sanitize_for_json(v) for k, v in obj.items()}
    elif isinstance(obj, (list, tuple)):
        return [_sanitize_for_json(v) for v in obj]
    elif isinstance(obj, (datetime, date)):
        return obj.isoformat()
    elif isinstance(obj, (bool, int, float, str, type(None))):
        return obj
    else:
        try:
            import json as _json; _json.dumps(obj)
            return obj
        except (TypeError, ValueError):
            return str(obj)


DB_PATH = "/home/claude/phishguard/data/scans.db"


class ScanHistoryDB:
    """SQLite-based scan history storage."""

    def __init__(self):
        os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
        self._init_db()
        self._seed_demo_data()

    def _init_db(self):
        with sqlite3.connect(DB_PATH) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS scans (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id TEXT UNIQUE NOT NULL,
                    url TEXT NOT NULL,
                    risk_score REAL,
                    risk_level TEXT,
                    classification TEXT,
                    confidence REAL,
                    recommendation TEXT,
                    indicators TEXT,
                    checks_json TEXT,
                    module_scores TEXT,
                    timestamp TEXT,
                    scan_duration_ms REAL
                )
            """)
            conn.commit()

    def _seed_demo_data(self):
        """Seed with realistic demo scan data."""
        count = self.get_total_count()
        if count > 0:
            return

        demo_scans = [
            {
                "scan_id": "DEMO0001", "url": "https://paypa1-secure.login-verify.tk/account",
                "risk_score": 94.2, "risk_level": "CRITICAL", "classification": "CONFIRMED_PHISHING",
                "confidence": 98.0, "recommendation": "[CRITICAL] DO NOT VISIT - High confidence phishing site",
                "indicators": json.dumps([
                    {"source": "URL Analysis", "check": "Brand Spoofing", "detail": "Domain spoofs PayPal", "severity": 35},
                    {"source": "Domain Intelligence", "check": "Newly Registered", "detail": "Domain 3 days old", "severity": 35},
                    {"source": "Content Analysis", "check": "Brand Impersonation", "detail": "PayPal branding on non-PayPal domain", "severity": 35},
                ]),
                "checks_json": "{}", "module_scores": json.dumps({"url_analysis": 85, "domain_intelligence": 90, "ssl_inspection": 70, "ml_detection": 95, "content_analysis": 88, "threat_intelligence": 60}),
                "timestamp": (datetime.utcnow() - timedelta(hours=2)).isoformat(), "scan_duration_ms": 1240
            },
            {
                "scan_id": "DEMO0002", "url": "https://amazon.com/deals",
                "risk_score": 4.1, "risk_level": "MINIMAL", "classification": "LIKELY_SAFE",
                "confidence": 95.0, "recommendation": "[SAFE] Appears safe - Standard precautions apply",
                "indicators": json.dumps([]),
                "checks_json": "{}", "module_scores": json.dumps({"url_analysis": 5, "domain_intelligence": 2, "ssl_inspection": 0, "ml_detection": 3, "content_analysis": 8, "threat_intelligence": 0}),
                "timestamp": (datetime.utcnow() - timedelta(hours=5)).isoformat(), "scan_duration_ms": 890
            },
            {
                "scan_id": "DEMO0003", "url": "http://192.168.1.1/admin/login",
                "risk_score": 72.5, "risk_level": "HIGH", "classification": "LIKELY_PHISHING",
                "confidence": 85.0, "recommendation": "[HIGH] Strongly suspected phishing - Avoid",
                "indicators": json.dumps([
                    {"source": "URL Analysis", "check": "IP Address Used", "detail": "IP used instead of domain", "severity": 25},
                    {"source": "SSL Inspection", "check": "No SSL Certificate", "detail": "HTTP only", "severity": 10},
                ]),
                "checks_json": "{}", "module_scores": json.dumps({"url_analysis": 70, "domain_intelligence": 75, "ssl_inspection": 40, "ml_detection": 80, "content_analysis": 60, "threat_intelligence": 0}),
                "timestamp": (datetime.utcnow() - timedelta(hours=8)).isoformat(), "scan_duration_ms": 650
            },
            {
                "scan_id": "DEMO0004", "url": "https://microsoft-account-verify.online/login",
                "risk_score": 87.3, "risk_level": "CRITICAL", "classification": "CONFIRMED_PHISHING",
                "confidence": 92.0, "recommendation": "[CRITICAL] DO NOT VISIT - High confidence phishing site",
                "indicators": json.dumps([
                    {"source": "URL Analysis", "check": "Brand Name Embedding", "detail": "Embeds 'microsoft' in suspicious domain", "severity": 20},
                    {"source": "Domain Intelligence", "check": "Newly Registered", "detail": "Domain 12 days old", "severity": 35},
                    {"source": "ML Detection", "check": "High Phishing Probability", "detail": "87% phishing probability", "severity": 35},
                ]),
                "checks_json": "{}", "module_scores": json.dumps({"url_analysis": 75, "domain_intelligence": 88, "ssl_inspection": 45, "ml_detection": 92, "content_analysis": 85, "threat_intelligence": 50}),
                "timestamp": (datetime.utcnow() - timedelta(days=1)).isoformat(), "scan_duration_ms": 1580
            },
            {
                "scan_id": "DEMO0005", "url": "https://github.com/anthropics/anthropic-sdk-python",
                "risk_score": 2.0, "risk_level": "MINIMAL", "classification": "LIKELY_SAFE",
                "confidence": 98.0, "recommendation": "[SAFE] Appears safe - Standard precautions apply",
                "indicators": json.dumps([]),
                "checks_json": "{}", "module_scores": json.dumps({"url_analysis": 3, "domain_intelligence": 0, "ssl_inspection": 0, "ml_detection": 2, "content_analysis": 5, "threat_intelligence": 0}),
                "timestamp": (datetime.utcnow() - timedelta(days=1, hours=3)).isoformat(), "scan_duration_ms": 780
            },
            {
                "scan_id": "DEMO0006", "url": "https://netf1ix-renewal.xyz/account-suspended",
                "risk_score": 91.7, "risk_level": "CRITICAL", "classification": "CONFIRMED_PHISHING",
                "confidence": 96.0, "recommendation": "[CRITICAL] DO NOT VISIT - High confidence phishing site",
                "indicators": json.dumps([
                    {"source": "URL Analysis", "check": "Typosquatting", "detail": "'netf1ix' spoofs Netflix", "severity": 35},
                    {"source": "URL Analysis", "check": "Suspicious TLD", "detail": ".xyz domain", "severity": 15},
                    {"source": "Content Analysis", "check": "Login Form", "detail": "Password form on page", "severity": 25},
                ]),
                "checks_json": "{}", "module_scores": json.dumps({"url_analysis": 92, "domain_intelligence": 85, "ssl_inspection": 60, "ml_detection": 94, "content_analysis": 90, "threat_intelligence": 70}),
                "timestamp": (datetime.utcnow() - timedelta(days=2)).isoformat(), "scan_duration_ms": 1320
            },
            {
                "scan_id": "DEMO0007", "url": "https://login.suspicious-bank-secure.com/verify",
                "risk_score": 55.8, "risk_level": "MEDIUM", "classification": "SUSPICIOUS",
                "confidence": 78.0, "recommendation": "[MEDIUM] Suspicious - Exercise extreme caution",
                "indicators": json.dumps([
                    {"source": "URL Analysis", "check": "Suspicious Keywords", "detail": "login, secure, verify", "severity": 20},
                    {"source": "Domain Intelligence", "check": "Young Domain", "detail": "Domain 45 days old", "severity": 10},
                ]),
                "checks_json": "{}", "module_scores": json.dumps({"url_analysis": 55, "domain_intelligence": 45, "ssl_inspection": 20, "ml_detection": 65, "content_analysis": 50, "threat_intelligence": 0}),
                "timestamp": (datetime.utcnow() - timedelta(days=2, hours=5)).isoformat(), "scan_duration_ms": 920
            },
            {
                "scan_id": "DEMO0008", "url": "https://cloudflare.com",
                "risk_score": 1.5, "risk_level": "MINIMAL", "classification": "LIKELY_SAFE",
                "confidence": 99.0, "recommendation": "[SAFE] Appears safe - Standard precautions apply",
                "indicators": json.dumps([]),
                "checks_json": "{}", "module_scores": json.dumps({"url_analysis": 2, "domain_intelligence": 0, "ssl_inspection": 0, "ml_detection": 1, "content_analysis": 3, "threat_intelligence": 0}),
                "timestamp": (datetime.utcnow() - timedelta(days=3)).isoformat(), "scan_duration_ms": 560
            },
        ]

        for scan in demo_scans:
            self._insert(scan)

    def _insert(self, scan: Dict):
        try:
            with sqlite3.connect(DB_PATH) as conn:
                conn.execute("""
                    INSERT OR REPLACE INTO scans
                    (scan_id, url, risk_score, risk_level, classification, confidence,
                     recommendation, indicators, checks_json, module_scores, timestamp, scan_duration_ms)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    scan["scan_id"], scan["url"], scan["risk_score"], scan["risk_level"],
                    scan["classification"], scan["confidence"], scan["recommendation"],
                    scan["indicators"], scan["checks_json"], scan["module_scores"],
                    scan["timestamp"], scan["scan_duration_ms"]
                ))
                conn.commit()
        except Exception as e:
            pass

    def save(self, result: Dict):
        scan = {
            "scan_id": result.get("scan_id", ""),
            "url": result.get("url", ""),
            "risk_score": result.get("risk_score", 0),
            "risk_level": result.get("risk_level", ""),
            "classification": result.get("classification", ""),
            "confidence": result.get("confidence", 0),
            "recommendation": result.get("recommendation", ""),
            "indicators": json.dumps(result.get("indicators", [])),
            "checks_json": json.dumps(_sanitize_for_json(result.get("checks", {}))),
            "module_scores": json.dumps(
                result.get("checks", {}).get("risk_scoring", {}).get("module_scores", {})
            ),
            "timestamp": result.get("timestamp", datetime.utcnow().isoformat()),
            "scan_duration_ms": result.get("scan_duration_ms", 0)
        }
        self._insert(scan)

    def get_history(self, limit: int = 50, offset: int = 0) -> List[Dict]:
        with sqlite3.connect(DB_PATH) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute("""
                SELECT scan_id, url, risk_score, risk_level, classification,
                       confidence, recommendation, indicators, module_scores, timestamp, scan_duration_ms
                FROM scans ORDER BY timestamp DESC LIMIT ? OFFSET ?
            """, (limit, offset)).fetchall()

        result = []
        for row in rows:
            d = dict(row)
            d["indicators"] = json.loads(d["indicators"] or "[]")
            d["module_scores"] = json.loads(d["module_scores"] or "{}")
            result.append(d)
        return result

    def get_by_id(self, scan_id: str) -> Optional[Dict]:
        with sqlite3.connect(DB_PATH) as conn:
            conn.row_factory = sqlite3.Row
            row = conn.execute("SELECT * FROM scans WHERE scan_id = ?", (scan_id,)).fetchone()
        if not row:
            return None
        d = dict(row)
        d["indicators"] = json.loads(d.get("indicators") or "[]")
        d["checks"] = json.loads(d.get("checks_json") or "{}")
        d["module_scores"] = json.loads(d.get("module_scores") or "{}")
        return d

    def get_total_count(self) -> int:
        with sqlite3.connect(DB_PATH) as conn:
            return conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0]

    def get_statistics(self) -> Dict:
        with sqlite3.connect(DB_PATH) as conn:
            total = conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
            phishing = conn.execute(
                "SELECT COUNT(*) FROM scans WHERE classification IN ('CONFIRMED_PHISHING', 'LIKELY_PHISHING')"
            ).fetchone()[0]
            suspicious = conn.execute(
                "SELECT COUNT(*) FROM scans WHERE classification = 'SUSPICIOUS'"
            ).fetchone()[0]
            safe = conn.execute(
                "SELECT COUNT(*) FROM scans WHERE classification = 'LIKELY_SAFE'"
            ).fetchone()[0]
            avg_score = conn.execute("SELECT AVG(risk_score) FROM scans").fetchone()[0] or 0
            avg_duration = conn.execute("SELECT AVG(scan_duration_ms) FROM scans").fetchone()[0] or 0

        return {
            "total_scans": total,
            "phishing_detected": phishing,
            "suspicious_detected": suspicious,
            "safe_scanned": safe,
            "detection_rate": round((phishing / total * 100), 1) if total > 0 else 0,
            "average_risk_score": round(avg_score, 1),
            "average_scan_duration_ms": round(avg_duration, 1),
            "threats_blocked": phishing + suspicious
        }

    def get_trends(self) -> List[Dict]:
        """Get scan trends for the past 7 days."""
        with sqlite3.connect(DB_PATH) as conn:
            rows = conn.execute("""
                SELECT substr(timestamp, 1, 10) as day,
                       COUNT(*) as total,
                       SUM(CASE WHEN classification IN ('CONFIRMED_PHISHING','LIKELY_PHISHING') THEN 1 ELSE 0 END) as phishing,
                       SUM(CASE WHEN classification = 'LIKELY_SAFE' THEN 1 ELSE 0 END) as safe
                FROM scans
                GROUP BY day ORDER BY day DESC LIMIT 7
            """).fetchall()
        return [{"day": r[0], "total": r[1], "phishing": r[2], "safe": r[3]} for r in rows]

    def get_threat_distribution(self) -> Dict:
        with sqlite3.connect(DB_PATH) as conn:
            rows = conn.execute("""
                SELECT classification, COUNT(*) as count FROM scans GROUP BY classification
            """).fetchall()
        return {r[0]: r[1] for r in rows}

    def get_top_indicators(self) -> List[Dict]:
        """Get most common phishing indicators."""
        with sqlite3.connect(DB_PATH) as conn:
            rows = conn.execute(
                "SELECT indicators FROM scans WHERE indicators != '[]' AND indicators IS NOT NULL LIMIT 100"
            ).fetchall()

        counter = {}
        for row in rows:
            try:
                indicators = json.loads(row[0])
                for ind in indicators:
                    check = ind.get("check", "")
                    counter[check] = counter.get(check, 0) + 1
            except Exception:
                pass

        top = sorted(counter.items(), key=lambda x: x[1], reverse=True)[:10]
        return [{"indicator": k, "count": v} for k, v in top]

    def prune(self, keep: int = 5000):
        """Delete oldest scans keeping only the most recent 'keep' entries."""
        with sqlite3.connect(DB_PATH) as conn:
            conn.execute("""
                DELETE FROM scans WHERE id NOT IN (
                    SELECT id FROM scans ORDER BY timestamp DESC LIMIT ?
                )
            """, (keep,))
            conn.commit()

    def clear(self):
        with sqlite3.connect(DB_PATH) as conn:
            conn.execute("DELETE FROM scans")
            conn.commit()
