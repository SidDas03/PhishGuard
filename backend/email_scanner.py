"""
Email Scanner — Extract URLs from email body and scan them all.
Detects phishing in: HTML emails, plain text emails, .eml format
"""
import re
from typing import Dict, Any, List, Callable
from datetime import datetime, timezone
import urllib.parse

URL_PATTERN = re.compile(
    r'https?://[^\s<>"\')\]\}\\,;]+',
    re.IGNORECASE
)

OBFUSCATED_PATTERN = re.compile(
    r'hxxps?://[^\s<>"\')\]\}\\,;]+|'
    r'h\[t\]tps?://[^\s<>"\')\]\}\\,;]+|'
    r'ht\[tp\]s?://[^\s<>"\')\]\}\\,;]+',
    re.IGNORECASE
)

PHISHING_SUBJECT_WORDS = [
    "urgent", "immediate", "suspended", "verify", "confirm", "unusual",
    "alert", "warning", "locked", "compromised", "action required",
    "click here", "limited time", "account closed", "won", "prize",
    "invoice", "payment failed", "delivery failed", "refund",
]

PHISHING_SENDER_PATTERNS = [
    r"no.?reply.*@(?!.*\.(com|org|net|gov|edu)$)",
    r"security.*@(?!paypal|google|microsoft|apple|amazon)",
    r"support.*@.*\.(tk|ml|ga|cf|gq|xyz|top|online|site)",
]


class EmailScanner:

    def scan(self, body: str, subject: str = "", sender: str = "",
             run_scan_fn: Callable = None) -> Dict[str, Any]:
        """
        Extract all URLs from email and scan each one.
        Returns full analysis including email-level risk indicators.
        """
        raw_urls  = URL_PATTERN.findall(body)
        obf_urls  = OBFUSCATED_PATTERN.findall(body)

        deobf = []
        for u in obf_urls:
            clean = u.replace("hxxp", "http").replace("[t]", "t").replace("[tp]", "tp")
            deobf.append(clean)

        all_urls = list(dict.fromkeys(raw_urls + deobf))
        MAX_URLS = 50
        truncated = len(all_urls) > MAX_URLS
        all_urls  = all_urls[:MAX_URLS]

        email_indicators = self._analyze_email(subject, sender, body, obf_urls)

        url_results = []
        if run_scan_fn:
            for url in all_urls:
                try:
                    r = run_scan_fn(url, {
                        "check_ssl": True,
                        "check_content": False,
                        "check_threat_intel": False,
                    })
                    url_results.append(r)
                except Exception as e:
                    url_results.append({
                        "url": url, "error": str(e)[:60], "status": "failed"
                    })
        phishing   = [r for r in url_results if r.get("risk_score", 0) >= 65]
        suspicious = [r for r in url_results if 45 <= r.get("risk_score", 0) < 65]
        safe       = [r for r in url_results if r.get("risk_score", 0) < 45
                      and "error" not in r]
                 
        url_max_score = max((r.get("risk_score", 0) for r in url_results), default=0)
        email_risk    = min(url_max_score + len(email_indicators) * 5, 100)

        level = "LIKELY_PHISHING" if email_risk >= 65 else \
                "SUSPICIOUS"      if email_risk >= 45 else \
                "LIKELY_SAFE"

        return {
            "email_risk_score":    round(email_risk, 1),
            "email_risk_level":    level,
            "subject":             subject[:200] if subject else "",
            "sender":              sender[:200]  if sender  else "",
            "urls_found":          len(all_urls),
            "urls_truncated":      truncated,
            "obfuscated_urls":     len(obf_urls),
            "phishing_urls":       len(phishing),
            "suspicious_urls":     len(suspicious),
            "safe_urls":           len(safe),
            "email_indicators":    email_indicators,
            "url_results":         url_results,
            "top_threats":         sorted(phishing, key=lambda x: x.get("risk_score", 0),
                                          reverse=True)[:3],
            "timestamp":           datetime.now(timezone.utc).isoformat(),
        }

    def _analyze_email(self, subject: str, sender: str,
                       body: str, obf_urls: list) -> List[Dict]:
        indicators = []
        sl = subject.lower()
        bl = body.lower()

        found_kw = [w for w in PHISHING_SUBJECT_WORDS if w in sl]
        if len(found_kw) >= 2:
            indicators.append({
                "check":  "Multiple Phishing Keywords in Subject",
                "detail": f"Subject contains: {', '.join(found_kw[:4])}",
                "severity": 20
            })
        elif found_kw:
            indicators.append({
                "check":  "Phishing Keyword in Subject",
                "detail": f"Subject contains '{found_kw[0]}'",
                "severity": 10
            })

        if obf_urls:
            indicators.append({
                "check":  "Obfuscated URLs Detected",
                "detail": f"{len(obf_urls)} URLs obfuscated with hxxp:// or similar",
                "severity": 30
            })

        if sender and "@" in sender:
            domain = sender.split("@")[-1].rstrip(">").strip().lower()
            for pat in PHISHING_SENDER_PATTERNS:
                if re.search(pat, sender.lower()):
                    indicators.append({
                        "check":  "Suspicious Sender Domain",
                        "detail": f"Sender '{sender[:60]}' matches phishing sender pattern",
                        "severity": 25
                    })
                    break

        if re.search(r"<form[^>]*action", body, re.IGNORECASE):
            indicators.append({
                "check":  "HTML Form in Email",
                "detail": "Email contains an HTML form — credential harvesting risk",
                "severity": 35
            
        urgency = re.findall(
            r"(within \d+ hours?|expires? (today|soon|in \d+)|last chance|final notice|"
            r"account will be (closed|deleted|suspended)|verify (now|immediately|today))",
            bl)
        if urgency:
            indicators.append({
                "check":  "Urgency Language",
                "detail": "Email uses time pressure tactics",
                "severity": 15
            })

        link_text = re.findall(r'href=["\']([^"\']+)["\'][^>]*>([^<]{4,50})</a>', body, re.I)
        for href, text in link_text[:10]:
            text_domain = re.search(r'https?://([^/\s]+)', text)
            href_domain = re.search(r'https?://([^/\s]+)', href)
            if text_domain and href_domain:
                if text_domain.group(1).lower() != href_domain.group(1).lower():
                    indicators.append({
                        "check":  "Link Text Mismatch",
                        "detail": f"Link shows '{text_domain.group(1)}' but goes to '{href_domain.group(1)}'",
                        "severity": 30
                    })
                    break

        return indicators
