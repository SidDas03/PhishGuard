"""
PhishGuard Risk Scorer — aggregates module scores into final verdict.
Designed to match VirusTotal-level accuracy using ensemble signals.
"""
from typing import Dict, Any

MODULE_WEIGHTS = {
    "url_analysis":         0.25,
    "domain_intelligence":  0.15,
    "ssl_inspection":       0.08,
    "ml_detection":         0.30, 
    "content_analysis":     0.07,
    "threat_intelligence":  0.15,  
}

THRESHOLDS = [
    (85, "CRITICAL", "CONFIRMED_PHISHING",  "[CRITICAL] DO NOT VISIT - Confirmed phishing site"),
    (65, "HIGH",     "LIKELY_PHISHING",      "[HIGH] Very likely phishing - Avoid this URL"),
    (45, "MEDIUM",   "SUSPICIOUS",           "[MEDIUM] Suspicious - Exercise extreme caution"),
    (25, "LOW",      "POTENTIALLY_UNSAFE",   "[LOW] Low risk - Proceed with caution"),
    (0,  "MINIMAL",  "LIKELY_SAFE",          "[SAFE] Appears safe - No significant threats detected"),
]


class RiskScorer:

    def compute(self, checks: Dict[str, Any]) -> Dict[str, Any]:
        weighted    = 0.0
        used_weight = 0.0
        all_indicators = []

        url_data    = checks.get("url_analysis", {})
        is_real_brand = url_data.get("real_brand", False)
        trusted_tld   = url_data.get("trusted_tld", False)

        for key, weight in MODULE_WEIGHTS.items():
            mod = checks.get(key, {})
            if not mod:
                continue
            raw = mod.get("score", 0)
            weighted    += raw * weight
            used_weight += weight
            for f in mod.get("findings", []):
                if f.get("flagged"):
                    all_indicators.append({
                        "source":   mod.get("module", key),
                        "check":    f.get("check", ""),
                        "detail":   f.get("detail", ""),
                        "severity": f.get("severity", 0),
                    })

        base = (weighted / used_weight) if used_weight > 0 else 0

        has_ip         = any("IP Address" in i["check"] for i in all_indicators)
        has_path_brand = any("Brand Domain in URL Path" in i["check"] for i in all_indicators)
        has_typosquat  = any("Spoofing" in i["check"] or "Typosquat" in i["check"]
                              or "Leet" in i["check"] for i in all_indicators)
        has_homograph  = any("Homograph" in i["check"] or "IDN" in i["check"]
                              for i in all_indicators)
        has_ti_confirmed = any(i.get("severity",0) >= 45 for i in all_indicators)
        ml_prob = checks.get("ml_detection", {}).get("phishing_probability", 0)

        ti_sources    = checks.get("threat_intelligence", {}).get("sources", {}) or {}
        vt_data       = ti_sources.get("virustotal", {}) or {}
        vt_stats      = vt_data.get("stats", {}) or {}
        vt_malicious  = int(vt_stats.get("malicious", 0))
        vt_suspicious = int(vt_stats.get("suspicious", 0))
        vt_flagged    = bool(vt_data.get("flagged", False))
        pt_verified   = bool(ti_sources.get("phishtank", {}).get("flagged", False))
        gsb_flagged   = bool(ti_sources.get("google_safe_browsing", {}).get("flagged", False))

        if ml_prob >= 0.90:
            base = max(base, 80.0)
        elif ml_prob >= 0.75:
            base = max(base, 65.0)
        elif ml_prob >= 0.50:
            base = max(base, 45.0)
        elif ml_prob <= 0.10 and is_real_brand:
            base = min(base, 15.0)   
        elif ml_prob <= 0.10 and trusted_tld:
            base = min(base, 30.0)  

        if has_path_brand:   base = max(base, 75.0)
        if has_typosquat:    base = max(base, 65.0)
        if has_homograph:    base = max(base, 70.0)
        if has_ip:           base = max(base, 55.0)
        if has_ti_confirmed: base = max(base, 90.0)

        if not is_real_brand and not trusted_tld:
            if vt_malicious >= 10:
                base = max(base, 90.0) 
            elif vt_malicious >= 5:
                base = max(base, 80.0) 
            elif vt_malicious >= 3:
                base = max(base, 70.0) 
            elif vt_malicious >= 1:
                base = max(base, 55.0)
            elif vt_flagged and vt_suspicious >= 3:
                base = max(base, 50.0)  
            if pt_verified:
                base = max(base, 90.0) 
            if gsb_flagged:
                base = max(base, 85.0) 

        if is_real_brand and ml_prob < 0.3:
            base = min(base, 20.0)
        if trusted_tld and ml_prob < 0.3 and not has_path_brand:
            base = min(base, 30.0)

        final = round(min(max(base, 0), 100), 1)

        level, cls, rec = "MINIMAL", "LIKELY_SAFE", "[SAFE] Appears safe"
        for threshold, lvl, classification, recommendation in THRESHOLDS:
            if final >= threshold:
                level, cls, rec = lvl, classification, recommendation
                break

        all_indicators.sort(key=lambda x: x.get("severity", 0), reverse=True)
        confidence = round(min((used_weight / sum(MODULE_WEIGHTS.values())) * 100, 100), 1)

        return {
            "score":          final,
            "level":          level,
            "classification": cls,
            "recommendation": rec,
            "confidence":     confidence,
            "indicators":     all_indicators[:10],
            "module_scores":  {k: checks.get(k,{}).get("score",0) for k in MODULE_WEIGHTS},
        }
