"""
Threat Intelligence v2 — VirusTotal, Google Safe Browsing, PhishTank
Fixed: Submit-then-poll flow for VT (gets fresh results like the website does)
Fixed: All code paths return a dict (no implicit None returns)
Fixed: Handles 404, 429, 401 from VT API properly
"""
import os, base64, requests, time
from typing import Dict, Any

requests.packages.urllib3.disable_warnings()

VT_POLL_WAIT    = 3   
VT_POLL_RETRIES = 6    
VT_TIMEOUT      = 15  


def _safe(detail="", flagged=False, severity=0, **kw):
    """Always return a proper dict — never None."""
    return {"flagged": flagged, "detail": detail, "severity": severity, **kw}


class ThreatIntelligence:

    def __init__(self):
        self.vt_key  = os.environ.get("VIRUSTOTAL_API_KEY", "")
        self.gsb_key = os.environ.get("GOOGLE_SAFE_BROWSING_KEY", "")
        self.pt_key  = os.environ.get("PHISHTANK_API_KEY", "")

    def lookup(self, url: str) -> Dict[str, Any]:
        findings, score, data = [], 0, {}

        for fn, label in [
            (self._virustotal, "virustotal"),
            (self._google_sb,  "google_safe_browsing"),
            (self._phishtank,  "phishtank"),
        ]:
            try:
                r = fn(url)
            except Exception as e:
                r = _safe(detail=f"Check error: {str(e)[:80]}")

            if not isinstance(r, dict):
                r = _safe(detail="Unexpected response format")
            r.setdefault("flagged",  False)
            r.setdefault("severity", 0)

            data[label] = r

            if r.get("flagged"):
                findings.append({
                    "flagged":  True,
                    "check":    r.get("check_name", "Threat detected"),
                    "detail":   r.get("detail", ""),
                    "severity": r.get("severity", 0),
                })
                score += r.get("severity", 0)

        return {
            "module":         "Threat Intelligence",
            "score":          min(score, 100),
            "findings_count": len(findings),
            "findings":       findings,
            "sources":        data,
        }

    def _virustotal(self, url: str) -> Dict:
        if not self.vt_key:
            return _safe(
                detail="VirusTotal API key not set — add VIRUSTOTAL_API_KEY env var.",
                status="not_configured",
            )

        hdrs    = {"x-apikey": self.vt_key}
        url_id  = base64.urlsafe_b64encode(url.encode()).decode().strip("=")

        try:
            resp = requests.get(
                f"https://www.virustotal.com/api/v3/urls/{url_id}",
                headers=hdrs, timeout=VT_TIMEOUT,
            )

            if resp.status_code == 200:
                result = self._parse_vt_analysis(resp.json())
                if result is not None:
                    return result

            elif resp.status_code == 401:
                return _safe(detail="VirusTotal API key is invalid or expired.")

            elif resp.status_code == 429:
                return _safe(
                    detail="VirusTotal rate limit reached (free tier: 4 req/min). "
                           "Wait 60 seconds and try again."
                )
s
        except requests.exceptions.Timeout:
            return _safe(detail="VirusTotal request timed out.")
        except requests.exceptions.ConnectionError:
            return _safe(detail="Could not connect to VirusTotal.")
        except Exception as e:
            return _safe(detail=f"VirusTotal error: {str(e)[:80]}")

        try:
            sub = requests.post(
                "https://www.virustotal.com/api/v3/urls",
                headers=hdrs,
                data={"url": url},
                timeout=VT_TIMEOUT,
            )

            if sub.status_code == 401:
                return _safe(detail="VirusTotal API key is invalid or expired.")
            if sub.status_code == 429:
                return _safe(detail="VirusTotal rate limit reached. Wait 60s and retry.")
            if sub.status_code not in (200, 201):
                return _safe(
                    detail=f"VirusTotal submission returned HTTP {sub.status_code}. "
                           "Try scanning again in 60 seconds."
                )

            analysis_id = sub.json().get("data", {}).get("id", "")

        except Exception as e:
            return _safe(detail=f"VirusTotal submission failed: {str(e)[:80]}")

        if analysis_id:
            for attempt in range(VT_POLL_RETRIES):
                time.sleep(VT_POLL_WAIT)
                try:
                    poll = requests.get(
                        f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
                        headers=hdrs, timeout=VT_TIMEOUT,
                    )
                    if poll.status_code == 200:
                        poll_data   = poll.json()
                        poll_status = (poll_data.get("data", {})
                                                .get("attributes", {})
                                                .get("status", ""))
                        if poll_status == "completed":
                            result = self._parse_vt_analysis(poll_data)
                            if result is not None:
                                return result
                    elif poll.status_code == 429:
                        return _safe(detail="VirusTotal rate limit reached during polling.")
                except Exception:
                    pass

        return _safe(
            detail="URL submitted to VirusTotal for analysis. "
                   "Scan again in 60 seconds for results.",
            status="submitted",
        )

    def _parse_vt_analysis(self, data: dict):
        """
        Parse a VT analysis response (from GET /urls/{id} or GET /analyses/{id}).
        Returns a result dict, or None if stats are not available yet.
        """
        attrs  = data.get("data", {}).get("attributes", {})
        stats  = attrs.get("last_analysis_stats", {}) or attrs.get("stats", {})

        if not stats:
            return None  

        mal   = int(stats.get("malicious",  0))
        sus   = int(stats.get("suspicious", 0))
        total = sum(int(v) for v in stats.values())

        if total == 0:
            return None 

        if mal >= 10:
            return _safe(
                flagged=True, severity=50,
                check_name=f"VirusTotal: {mal}/{total} engines flagged",
                detail=f"{mal} security vendors confirmed this URL as malicious",
                stats=stats,
            )
        if mal >= 5:
            return _safe(
                flagged=True, severity=40,
                check_name=f"VirusTotal: {mal}/{total} engines flagged",
                detail=f"{mal} security vendors flagged this URL as malicious",
                stats=stats,
            )
        if mal >= 3:
            return _safe(
                flagged=True, severity=30,
                check_name=f"VirusTotal: {mal}/{total} engines flagged",
                detail=f"{mal} malicious detections, {sus} suspicious out of {total} engines",
                stats=stats,
            )
        if mal >= 1:
            return _safe(
                flagged=True, severity=20,
                check_name="VirusTotal: Low detections",
                detail=f"{mal} malicious, {sus} suspicious out of {total} engines",
                stats=stats,
            )
        if sus >= 3:
            return _safe(
                flagged=True, severity=10,
                check_name="VirusTotal: Suspicious detections",
                detail=f"{sus} engines flagged as suspicious out of {total}",
                stats=stats,
            )
        return _safe(
            flagged=False,
            detail=f"Clean — {total} engines checked, 0 malicious detections",
            stats=stats,
        )

    def _google_sb(self, url: str) -> Dict:
        if not self.gsb_key:
            return _safe(
                detail="Google Safe Browsing key not set — add GOOGLE_SAFE_BROWSING_KEY env var.",
                status="not_configured",
            )
        try:
            api = (f"https://safebrowsing.googleapis.com/v4/"
                   f"threatMatches:find?key={self.gsb_key}")
            payload = {
                "client": {"clientId": "phishguard", "clientVersion": "5.0"},
                "threatInfo": {
                    "threatTypes":     ["MALWARE", "SOCIAL_ENGINEERING",
                                        "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                    "platformTypes":   ["ANY_PLATFORM"],
                    "threatEntryTypes":["URL"],
                    "threatEntries":   [{"url": url}],
                },
            }
            resp = requests.post(api, json=payload, timeout=10)

            if resp.status_code == 200:
                matches = resp.json().get("matches", [])
                if matches:
                    tt = matches[0].get("threatType", "UNKNOWN")
                    return _safe(
                        flagged=True, severity=45,
                        check_name=f"Google Safe Browsing: {tt}",
                        detail=f"URL flagged as {tt} by Google Safe Browsing",
                    )
                return _safe(detail="Clean — Google Safe Browsing found no threats")
            elif resp.status_code == 400:
                return _safe(detail="Google Safe Browsing: bad request (check API key)")
            elif resp.status_code == 403:
                return _safe(detail="Google Safe Browsing: API key not authorised")
            else:
                return _safe(detail=f"Google Safe Browsing returned HTTP {resp.status_code}")

        except requests.exceptions.Timeout:
            return _safe(detail="Google Safe Browsing request timed out.")
        except requests.exceptions.ConnectionError:
            return _safe(detail="Could not connect to Google Safe Browsing.")
        except Exception as e:
            return _safe(detail=f"Google Safe Browsing error: {str(e)[:80]}")

    def _phishtank(self, url: str) -> Dict:
        try:
            params = {"url": url, "format": "json", "app_key": self.pt_key or ""}
            resp = requests.post(
                "https://checkurl.phishtank.com/checkurl/",
                data=params,
                headers={"User-Agent": "phishguard/5.0"},
                timeout=10,
            )
            if resp.status_code == 200:
                results = resp.json().get("results", {})
                if results.get("in_database") and results.get("valid"):
                    return _safe(
                        flagged=True, severity=50,
                        check_name="PhishTank: Verified phishing URL",
                        detail="Confirmed phishing URL in PhishTank community database",
                    )
                if results.get("in_database"):
                    return _safe(
                        flagged=True, severity=25,
                        check_name="PhishTank: In database (unverified)",
                        detail="URL found in PhishTank database (not yet community-verified)",
                    )
                return _safe(detail="Not found in PhishTank database")
            return _safe(detail=f"PhishTank returned HTTP {resp.status_code}")
        except requests.exceptions.Timeout:
            return _safe(detail="PhishTank request timed out.")
        except requests.exceptions.ConnectionError:
            return _safe(detail="Could not connect to PhishTank.")
        except Exception as e:
            return _safe(detail=f"PhishTank error: {str(e)[:80]}")
