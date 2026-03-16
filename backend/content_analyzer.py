"""
Webpage Content Analyzer - Fixed false positives:
- Brand impersonation now requires login form + high mention count
- Trusted TLDs (.edu/.gov) get significantly reduced scoring
- Much higher mention thresholds before flagging
"""
import re
import urllib.parse
import requests
from typing import Dict, Any
from bs4 import BeautifulSoup
from url_analyzer import extract_domain_parts, is_trusted_tld

requests.packages.urllib3.disable_warnings()

BRAND_DOMAINS = {
    "paypal": ["paypal.com"],
    "amazon": ["amazon.com","amazon.co.uk","amazon.in","amazon.de","aws.amazon.com"],
    "apple": ["apple.com","icloud.com"],
    "microsoft": ["microsoft.com","live.com","outlook.com","office.com","microsoftonline.com"],
    "google": ["google.com","gmail.com","accounts.google.com","googleapis.com"],
    "netflix": ["netflix.com"],
    "facebook": ["facebook.com","fb.com","meta.com"],
    "chase": ["chase.com"],
    "bankofamerica": ["bankofamerica.com"],
    "wellsfargo": ["wellsfargo.com"],
}

BRAND_INDICATORS = {
    "paypal":    ["paypal","pypl","pp-logo"],
    "amazon":    ["amazon","a-logo","amzn"],
    "apple":     ["apple","apple-id","icloud"],
    "microsoft": ["microsoft","office365","outlook","msft"],
    "google":    ["google","gmail"],
    "netflix":   ["netflix","nflx"],
    "facebook":  ["facebook","fb-logo","meta"],
    "chase":     ["chase","jpmorgan"],
    "bankofamerica": ["bankofamerica","bofa"],
    "wellsfargo":["wellsfargo","wells-fargo"],
}

SUSPICIOUS_JS = [
    (r"document\.cookie",               "Cookie theft attempt"),
    (r"window\.location\s*=",           "Page redirect"),
    (r"\beval\s*\(",                     "Eval obfuscation"),
    (r"\bunescape\s*\(",                 "String deobfuscation"),
    (r"fromCharCode",                    "Char-code obfuscation"),
    (r"\batob\s*\(",                     "Base64 decode"),
    (r"onkeypress|onkeydown",           "Possible keylogger"),
    (r"navigator\.sendBeacon",           "Beacon exfiltration"),
]

CREDENTIAL_FIELDS = ["password","passwd","pwd","pass","login","username",
                     "credit","card","cvv","ssn","pin","secret"]


class ContentAnalyzer:

    def analyze(self, url: str) -> Dict[str, Any]:
        findings, score = [], 0
        content_data = {}
        ext = extract_domain_parts(url)
        trusted = is_trusted_tld(ext.get("suffix",""))

        try:
            headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                       "AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36"}
            resp = requests.get(url, headers=headers, timeout=10,
                                allow_redirects=True, verify=False)
            html = resp.text
            soup = BeautifulSoup(html, "html.parser")

            checks = [
                self._check_login_forms(soup),
                self._check_brand_impersonation(soup, html, url, trusted),
                self._check_suspicious_js(html, trusted),
                self._check_hidden_iframes(soup),
                self._check_credential_harvesting(soup),
                self._check_external_form(soup, url),
                self._check_redirects(resp),
                self._check_favicon(soup, url),
            ]
            for chk in checks:
                if chk.get("flagged"):
                    if trusted:
                        chk["severity"] = chk.get("severity", 0) // 2
                    findings.append(chk)
                    score += chk.get("severity", 0)

            content_data = {
                "final_url": resp.url,
                "status_code": resp.status_code,
                "content_length": len(html),
                "title": (soup.title.string or "").strip() if soup.title else "",
                "forms_count": len(soup.find_all("form")),
                "scripts_count": len(soup.find_all("script")),
                "iframes_count": len(soup.find_all("iframe")),
            }

        except requests.exceptions.SSLError:
            findings.append({"flagged":True,"check":"SSL Error During Fetch",
                             "detail":"SSL error fetching content","severity":15 if not trusted else 5})
            score += 15 if not trusted else 5
        except requests.exceptions.Timeout:
            findings.append({"flagged":False,"check":"Timeout","detail":"Page timed out","severity":0})
        except requests.exceptions.ConnectionError:
            findings.append({"flagged":True,"check":"Connection Failed",
                             "detail":"Cannot connect to host","severity":10 if not trusted else 0})
            score += 10 if not trusted else 0
        except Exception as e:
            findings.append({"flagged":False,"check":"Content Fetch",
                             "detail":f"Could not fetch: {str(e)[:60]}","severity":0})

        return {"module":"Content Analysis","score":min(score,100),
                "findings_count":len([f for f in findings if f.get("flagged")]),
                "findings":findings,"page_data":content_data}

    def _check_login_forms(self, soup):
        pw_forms = 0
        for form in soup.find_all("form"):
            for inp in form.find_all("input"):
                t = (inp.get("type") or "").lower()
                n = (inp.get("name") or inp.get("id") or "").lower()
                if t == "password" or "password" in n:
                    pw_forms += 1; break
        if pw_forms >= 2:
            return {"flagged":True,"check":"Multiple Password Forms",
                    "detail":f"{pw_forms} forms with password fields","severity":25}
        if pw_forms == 1:
            return {"flagged":True,"check":"Login Form Detected",
                    "detail":"Password input form present on page","severity":10}
        return {"flagged":False,"check":"Form Analysis","severity":0}

    def _check_brand_impersonation(self, soup, html, url, trusted):
        ext = extract_domain_parts(url)
        actual_domain = ext.get("domain","").lower()
        actual_fqdn = ext.get("fqdn","").lower()
        html_lower = html.lower()
        title = (soup.title.string or "").lower() if soup.title else ""
        img_srcs = [img.get("src","").lower() for img in soup.find_all("img")]
        has_login = any(
            inp.get("type","").lower() == "password"
            for inp in soup.find_all("input")
        )

        for brand, indicators in BRAND_INDICATORS.items():
            brand_owned_domains = BRAND_DOMAINS.get(brand, [])
            is_real = any(actual_fqdn == d or actual_fqdn.endswith("."+d)
                         for d in brand_owned_domains)
            if is_real:
                continue

            if brand in actual_domain:
                continue

            mentions = sum(html_lower.count(ind) for ind in indicators)
            in_title = any(ind in title for ind in indicators)
            in_img_src = any(any(ind in s for ind in indicators) for s in img_srcs)

            if trusted:

                if in_title and has_login and mentions > 20:
                    return {"flagged":True,"check":"Brand Impersonation Detected",
                            "detail":f"Page impersonates {brand.title()} (domain: '{actual_domain}')",
                            "severity":20} 
                continue

            if in_title and has_login:
                return {"flagged":True,"check":"Brand Impersonation Detected",
                        "detail":f"Page impersonates {brand.title()} (domain: '{actual_domain}')",
                        "severity":35}
            if mentions > 15 and has_login:
                return {"flagged":True,"check":"Brand Impersonation (High Mentions + Login)",
                        "detail":f"{mentions} mentions of '{brand}' with login form present",
                        "severity":30}
            if in_img_src and has_login:
                return {"flagged":True,"check":"Brand Logo + Login Form",
                        "detail":f"'{brand}' logo detected with login form on non-{brand} domain",
                        "severity":25}

        return {"flagged":False,"check":"Brand Impersonation","severity":0}

    def _check_suspicious_js(self, html, trusted):
        matches = [desc for pat,desc in SUSPICIOUS_JS if re.search(pat, html, re.I)]
        threshold = 4 if trusted else 3
        if len(matches) >= threshold:
            return {"flagged":True,"check":"Multiple Suspicious JS Patterns",
                    "detail":f"Detected: {', '.join(matches[:4])}","severity":30}
        if len(matches) >= 2 and not trusted:
            return {"flagged":True,"check":"Suspicious JavaScript Pattern",
                    "detail":f"Detected: {', '.join(matches)}","severity":15}
        return {"flagged":False,"check":"JavaScript Analysis","severity":0}

    def _check_hidden_iframes(self, soup):
        hidden = []
        for f in soup.find_all("iframe"):
            style = f.get("style","").replace(" ","")
            w, h = f.get("width",""), f.get("height","")
            if ("display:none" in style or "visibility:hidden" in style
                    or w in ("0","1") or h in ("0","1")):
                hidden.append(f.get("src","?"))
        if hidden:
            return {"flagged":True,"check":"Hidden Iframes Detected",
                    "detail":f"{len(hidden)} hidden iframe(s) found","severity":25}
        return {"flagged":False,"check":"Iframe Analysis","severity":0}

    def _check_credential_harvesting(self, soup):
        sensitive = []
        for inp in soup.find_all("input"):
            n = (inp.get("name") or inp.get("id") or inp.get("placeholder") or "").lower()
            for f in CREDENTIAL_FIELDS:
                if f in n and f not in sensitive:
                    sensitive.append(f)
        if len(sensitive) >= 4:
            return {"flagged":True,"check":"Credential Harvesting Indicators",
                    "detail":f"Many sensitive fields: {', '.join(sensitive[:5])}","severity":30}
        return {"flagged":False,"check":"Credential Fields","severity":0}

    def _check_external_form(self, soup, url):
        ext = extract_domain_parts(url)
        page_root = f"{ext.get('domain','')}.{ext.get('suffix','')}"
        for form in soup.find_all("form"):
            action = form.get("action","")
            if action and action.startswith("http"):
                aext = extract_domain_parts(action)
                aroot = f"{aext.get('domain','')}.{aext.get('suffix','')}"
                if aroot and aroot != page_root:
                    return {"flagged":True,"check":"External Form Submission",
                            "detail":f"Form submits to external domain: {aroot}","severity":35}
        return {"flagged":False,"check":"Form Action Check","severity":0}

    def _check_redirects(self, resp):
        if len(resp.history) > 3:
            return {"flagged":True,"check":"Excessive Redirects",
                    "detail":f"{len(resp.history)} redirect chain detected","severity":20}
        return {"flagged":False,"check":"Redirect Chain","severity":0}

    def _check_favicon(self, soup, url):
        ext = extract_domain_parts(url)
        page_root = f"{ext.get('domain','')}.{ext.get('suffix','')}"
        for tag in soup.find_all("link", rel=lambda r: r and "icon" in " ".join(r).lower()):
            href = tag.get("href","")
            if href.startswith("http"):
                fext = extract_domain_parts(href)
                froot = f"{fext.get('domain','')}.{fext.get('suffix','')}"
                if froot and froot != page_root:
                    return {"flagged":True,"check":"Favicon from External Domain",
                            "detail":f"Favicon loaded from {froot}","severity":20}
        return {"flagged":False,"check":"Favicon Check","severity":0}
