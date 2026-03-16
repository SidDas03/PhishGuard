"""
Domain Intelligence — DNS resolution, domain structure, whitelist checks.
Uses PhishUSIIL feature extractor for consistency.
"""
import socket, math
from typing import Dict, Any
from feature_extractor import (
    extract_features, _split_domain, TOP_DOMAINS,
    PHISHING_TLDS, TRUSTED_TLDS, DIRTY_WORDS, BRAND_NAMES
)

WHITELIST = TOP_DOMAINS 


class DomainIntelligence:

    def analyze(self, url: str) -> Dict[str, Any]:
        import urllib.parse
        host    = urllib.parse.urlparse(url).hostname or ""
        parts   = _split_domain(host)
        domain  = parts["domain"].lower()
        tld     = parts["tld"].lower()
        subdomain = parts["subdomain"].lower()
        fqdn    = host.lower()

        trusted = tld in TRUSTED_TLDS
        whitelisted = domain in WHITELIST

        findings = []
        score    = 0
        if whitelisted:
            return {
                "module": "Domain Intelligence", "score": 0, "domain": fqdn,
                "findings_count": 0,
                "findings": [{"flagged": False, "check": "Trusted Domain",
                               "detail": f"'{domain}' is a well-known trusted domain",
                               "severity": 0}],
                "domain_data": {"domain": domain, "trusted": True},
                "dns_records": {},
            }

        dns = self._check_dns(f"{domain}.{tld}" if tld else domain, trusted)
        if dns["flagged"]:
            findings.append(dns)
            score += dns.get("severity", 0)

        if not whitelisted:
            sub_check = self._check_subdomain_impersonation(subdomain, domain)
            if sub_check["flagged"]:
                findings.append(sub_check)
                score += sub_check.get("severity", 0)

        if not trusted:
            ent = self._check_entropy(domain)
            if ent["flagged"]:
                findings.append(ent)
                score += ent.get("severity", 0)

        struct = self._check_structure(domain, trusted)
        if struct["flagged"]:
            findings.append(struct)
            score += struct.get("severity", 0)

        if not trusted:
            num = self._check_numeric(domain)
            if num["flagged"]:
                findings.append(num)
                score += num.get("severity", 0)

        if trusted:
            score = min(score, 20)

        return {
            "module": "Domain Intelligence",
            "score":  min(score, 100),
            "domain": fqdn,
            "findings_count": len([f for f in findings if f.get("flagged")]),
            "findings": findings,
            "domain_data": {"domain": domain, "tld": tld,
                            "subdomain": subdomain, "trusted": trusted},
            "dns_records": dns.get("records", {}),
        }

    def _check_dns(self, domain, trusted):
        try:
            ips = socket.getaddrinfo(domain, None)
            records = {"A": list({r[4][0] for r in ips if ":" not in r[4][0]})}
            return {"flagged": False, "check": "DNS Resolution",
                    "detail": f"Resolved to {len(records['A'])} address(es)",
                    "records": records, "severity": 0}
        except socket.gaierror:
            sev = 3 if trusted else 15
            return {"flagged": True, "check": "DNS Resolution Failed",
                    "detail": f"'{domain}' could not be resolved",
                    "severity": sev, "records": {}}
        except Exception:
            return {"flagged": False, "check": "DNS Check", "severity": 0, "records": {}}

    def _check_subdomain_impersonation(self, sub, domain):
        for brand in BRAND_NAMES:
            if len(brand) < 5: continue
            if brand in sub and brand != domain:
                return {"flagged": True, "check": "Brand Name in Subdomain",
                        "detail": f"Subdomain '{sub}' contains brand '{brand}'",
                        "severity": 25}
        return {"flagged": False, "check": "Subdomain Check", "severity": 0}

    def _check_entropy(self, domain):
        if len(domain) < 6:
            return {"flagged": False, "check": "Domain Entropy", "severity": 0}
        freq = {}
        for c in domain: freq[c] = freq.get(c, 0) + 1
        ent = -sum((f/len(domain))*math.log2(f/len(domain)) for f in freq.values())
        consonants = sum(1 for c in domain if c in "bcdfghjklmnpqrstvwxyz")
        vowels = sum(1 for c in domain if c in "aeiou")
        cv = consonants / max(vowels, 1)
        if ent > 4.0 and cv > 5.5:
            return {"flagged": True, "check": "High Domain Entropy (Possible DGA)",
                    "detail": f"Entropy {ent:.2f}, CV-ratio {cv:.1f} — looks auto-generated",
                    "severity": 18}
        return {"flagged": False, "check": "Domain Entropy",
                "detail": f"Entropy: {ent:.2f}", "severity": 0}

    def _check_structure(self, domain, trusted):
        hyphens = domain.count("-")
        if hyphens >= 3:
            return {"flagged": True, "check": "Excessive Hyphens",
                    "detail": f"Domain '{domain}' has {hyphens} hyphens",
                    "severity": 5 if trusted else 12}
        if len(domain) > 30 and not trusted:
            return {"flagged": True, "check": "Very Long Domain",
                    "detail": f"Domain '{domain}' is {len(domain)} chars",
                    "severity": 8}
        return {"flagged": False, "check": "Domain Structure", "severity": 0}

    def _check_numeric(self, domain):
        digits = sum(c.isdigit() for c in domain)
        ratio  = digits / max(len(domain), 1)
        if ratio > 0.6:
            return {"flagged": True, "check": "Numeric-Heavy Domain",
                    "detail": f"Domain is {ratio:.0%} digits — common in auto-generated phishing",
                    "severity": 12}
        return {"flagged": False, "check": "Numeric Domain", "severity": 0}
