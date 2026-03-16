"""
PhishGuard URL Analyzer — rule-based checks using PhishUSIIL feature set.
Complements the ML model with human-interpretable findings.
"""
import re, urllib.parse, ipaddress, math
from typing import Dict, Any
from feature_extractor import (
    extract_features, _split_domain, _is_ip, _brand_similarity,
    _path_brand_check, BRAND_NAMES, DIRTY_WORDS,
    PHISHING_TLDS, TOP_DOMAINS, LEGIT_TLDS
)

# Real brand domains — never flag these as suspicious
REAL_BRAND_DOMAINS = {
    "google","youtube","gmail","googlemail",
    "microsoft","office","outlook","live","hotmail","msn","bing","skype","xbox","linkedin",
    "apple","icloud",
    "amazon","aws","audible","twitch",
    "facebook","instagram","whatsapp","messenger","meta","oculus",
    "twitter","x",
    "paypal",
    "netflix",
    "github","gitlab",
    "dropbox",
    "spotify",
    "zoom",
    "slack",
    "discord",
    "adobe",
    "salesforce",
    "stripe",
    "shopify",
    "hubspot",
    "wordpress","wix","squarespace",
    "godaddy","namecheap","bluehost","hostgator","siteground",
    "cloudflare",
    "stackoverflow","reddit","medium","quora","tumblr",
    "wikipedia","britannica",
    "ebay","etsy","aliexpress","walmart","target","bestbuy",
    "chase","wellsfargo","bankofamerica","citibank","americanexpress",
    "discover","capitalone","ally","schwab","fidelity","vanguard",
    "coinbase","binance","kraken","robinhood","venmo","cashapp","zelle","wise","revolut",
    "dhl","fedex","ups","usps",
    "irs","fbi","cdc","nist","nsa",
    "mit","harvard","stanford","berkeley","oxford","cambridge",
    "bbc","cnn","nytimes","reuters","bloomberg","techcrunch","wired",
    "nytimes","washingtonpost","theguardian","forbes",
    "microsoftonline",
}

TRUSTED_TLDS = {"edu","gov","mil","ac","ac.uk","gov.uk","edu.au","gov.au"}


def extract_domain_parts(url: str) -> Dict:
    """Wrapper for compatibility with other modules."""
    try:
        host = urllib.parse.urlparse(url).hostname or ""
        parts = _split_domain(host)
        return {
            "domain":    parts["domain"],
            "subdomain": parts["subdomain"],
            "suffix":    parts["tld"],
            "fqdn":      host,
        }
    except Exception:
        return {"domain":"","subdomain":"","suffix":"","fqdn":""}


def is_trusted_tld(tld: str) -> bool:
    return tld.lower() in TRUSTED_TLDS


class URLAnalyzer:

    def analyze(self, url: str) -> Dict[str, Any]:
        findings = []
        score    = 0

        try:
            parsed   = urllib.parse.urlparse(url)
            host     = parsed.hostname or ""
            parts    = _split_domain(host)
            domain   = parts["domain"].lower()
            subdomain= parts["subdomain"].lower()
            tld      = parts["tld"].lower()
            fqdn     = host.lower()
            path     = parsed.path or ""
            query    = parsed.query or ""
            netloc   = parsed.netloc or ""
        except Exception:
            return {"module":"URL Analysis","score":0,"findings":[],"findings_count":0,"url_features":{}}

        # Extract full feature set
        feats = extract_features(url)

        # Is this a real brand domain? If so, skip most checks
        is_real_brand = domain in REAL_BRAND_DOMAINS
        trusted_tld   = tld in TRUSTED_TLDS

        # ── CHECK 1: IP address as domain ──
        if feats["is_domain_ip"]:
            findings.append({"flagged":True,"check":"IP Address as Domain",
                "detail":f"Raw IP {host} used instead of a domain name — very suspicious",
                "severity":35})
            score += 35

        # ── CHECK 2: Phishing TLD ──
        if feats["tld_is_phishing"] and not is_real_brand:
            findings.append({"flagged":True,"check":"High-Risk TLD",
                "detail":f"TLD '.{tld}' is in the top abused free/cheap TLDs for phishing",
                "severity":20})
            score += 20

        # ── CHECK 3: Brand similarity (typosquatting / leet) ──
        if feats["brand_similarity_score"] >= 0.8 and not is_real_brand:
            sim = feats["brand_similarity_score"]
            findings.append({"flagged":True,"check":"Brand Spoofing / Typosquatting",
                "detail":f"Domain '{domain}' closely resembles a known brand (similarity: {sim:.0%})",
                "severity":40})
            score += 40

        # ── CHECK 4: Brand in URL path (path-based impersonation) ──
        if feats["has_brand_in_path"] and not is_real_brand:
            findings.append({"flagged":True,"check":"Brand Domain in URL Path",
                "detail":f"Path contains a brand domain while actual host is '{fqdn}' — impersonation",
                "severity":50})
            score += 50

        # ── CHECK 5: Multiple dirty/suspicious words in domain ──
        if feats["num_dirty_words_domain"] >= 2 and not is_real_brand and not trusted_tld:
            findings.append({"flagged":True,"check":"Multiple Phishing Keywords in Domain",
                "detail":f"{feats['num_dirty_words_domain']} suspicious words in domain: "
                         + ", ".join(w for w in DIRTY_WORDS if w in (subdomain+" "+domain)),
                "severity":25})
            score += 25
        elif feats["num_dirty_words_domain"] == 1 and not is_real_brand and not trusted_tld:
            findings.append({"flagged":True,"check":"Suspicious Keyword in Domain",
                "detail":f"Domain contains phishing-related keyword",
                "severity":12})
            score += 12

        # ── CHECK 6: Deep subdomain chain ──
        if feats["num_subdomains"] >= 4 and not trusted_tld:
            findings.append({"flagged":True,"check":"Excessive Subdomain Depth",
                "detail":f"{feats['num_subdomains']}-level subdomain chain in '{subdomain}'",
                "severity":15})
            score += 15
        elif feats["num_subdomains"] >= 3 and not trusted_tld and not is_real_brand:
            findings.append({"flagged":True,"check":"Deep Subdomain Chain",
                "detail":f"{feats['num_subdomains']}-level subdomain: '{subdomain}'",
                "severity":8})
            score += 8

        # ── CHECK 7: No HTTPS ──
        if not feats["is_https"]:
            findings.append({"flagged":True,"check":"No HTTPS",
                "detail":"Unencrypted HTTP — any credentials would be transmitted in plaintext",
                "severity":10})
            score += 10

        # ── CHECK 8: URL obfuscation ──
        if feats["num_at_symbols"]:
            findings.append({"flagged":True,"check":"@ Symbol in URL",
                "detail":"@ in URL authority causes the browser to redirect to what follows it",
                "severity":30})
            score += 30
        if feats["has_obfuscation"] and feats["num_obfuscated_chars"] > 5:
            findings.append({"flagged":True,"check":"URL Encoding Obfuscation",
                "detail":f"{feats['num_obfuscated_chars']} percent-encoded chars — possible obfuscation",
                "severity":15})
            score += 15

        # ── CHECK 9: IDN / Homograph ──
        if feats["is_idn"]:
            findings.append({"flagged":True,"check":"IDN / Homograph Attack",
                "detail":"URL contains Unicode characters that look like ASCII — visual deception",
                "severity":35})
            score += 35

        # ── CHECK 10: Non-standard port ──
        if feats["has_nonstandard_port"]:
            findings.append({"flagged":True,"check":"Non-Standard Port",
                "detail":f"Unusual port in URL — legitimate services rarely use non-standard ports",
                "severity":10})
            score += 10

        # ── CHECK 11: Double slash redirect ──
        if feats["has_double_slash"]:
            findings.append({"flagged":True,"check":"Double Slash Redirect",
                "detail":"Double slash in path — browser redirect trick",
                "severity":10})
            score += 10

        # ── CHECK 12: Suspicious subdomain (brand in subdomain for non-brand) ──
        if not is_real_brand and not trusted_tld:
            sub_brand = any(b in subdomain for b in BRAND_NAMES if len(b) > 4)
            if sub_brand and not any(subdomain.split(".")[-1] == b for b in REAL_BRAND_DOMAINS):
                brand_found = [b for b in BRAND_NAMES if b in subdomain and len(b) > 4]
                findings.append({"flagged":True,"check":"Brand Name in Subdomain",
                    "detail":f"Subdomain '{subdomain}' contains brand '{brand_found[0]}' — classic phishing pattern",
                    "severity":30})
                score += 30

        # ── CHECK 13: Very long URL ──
        if feats["url_length"] > 200 and not trusted_tld:
            findings.append({"flagged":True,"check":"Excessively Long URL",
                "detail":f"URL is {feats['url_length']} characters — phishing URLs are often padded",
                "severity":8})
            score += 8

        # Trust score adjustment
        if is_real_brand:
            score = min(score, 10)  # Cap at 10 for real brands
        if trusted_tld:
            score = min(score, 25)  # Cap at 25 for .edu/.gov

        return {
            "module":        "URL Analysis",
            "score":         min(score, 100),
            "findings_count": len([f for f in findings if f.get("flagged")]),
            "findings":       findings,
            "trusted_tld":   trusted_tld,
            "real_brand":    is_real_brand,
            "url_features":  feats,
        }
