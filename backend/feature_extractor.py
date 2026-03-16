"""
PhishGuard Feature Extractor — implements the PhishUSIIL feature set
87 carefully engineered features for phishing detection.
Based on: "PhiUSIIL Phishing URL (Website) Dataset" (Hannousse, 2022)
"""
import re, math, urllib.parse, ipaddress, socket
from typing import Dict, Any

# ── Alexa/Tranco-inspired top domain list (top brands, no phishing sites)
TOP_DOMAINS = {
    "google","youtube","facebook","twitter","instagram","linkedin","amazon",
    "microsoft","apple","netflix","reddit","wikipedia","github","stackoverflow",
    "yahoo","ebay","paypal","dropbox","twitch","spotify","adobe","salesforce",
    "cloudflare","wordpress","shopify","zoom","slack","discord","telegram",
    "whatsapp","tiktok","pinterest","snapchat","tumblr","quora","medium",
    "mailchimp","hubspot","godaddy","namecheap","bluehost","hostgator",
    "mozilla","opera","brave","firefox","chrome","edge","safari",
    "nytimes","bbc","cnn","reuters","forbes","bloomberg","techcrunch",
    "stripe","square","braintree","wise","revolut","coinbase","binance",
    "aws","azure","gcp","oracle","ibm","cisco","vmware","intel","amd",
    "samsung","sony","lg","dell","hp","lenovo","asus","acer","toshiba",
    "chase","wellsfargo","bankofamerica","citibank","hsbc","barclays",
    "americanexpress","discover","capitalone","ally","schwab","fidelity",
    "mit","harvard","stanford","berkeley","oxford","cambridge",
    "gov","mil","edu","ac",  # trusted second-level TLDs
}

# TLDs with high legitimate usage probability
LEGIT_TLDS = {
    "com","org","net","edu","gov","mil","io","co","us","uk","ca","au",
    "de","fr","jp","cn","in","br","mx","nl","se","no","dk","fi","be",
    "ch","at","pl","cz","sk","hu","ro","bg","hr","lt","lv","ee","si",
    "ie","pt","es","it","gr","tr","ru","ua","kz","sg","hk","tw","kr",
    "nz","za","ar","cl","pe","co.uk","co.in","com.au","co.nz","co.za",
    "gov.uk","ac.uk","edu.au","gov.au","co.jp",
}

# TLDs heavily abused for phishing (source: APWG, VirusTotal reports)
PHISHING_TLDS = {
    "tk","ml","ga","cf","gq",   # Freenom free TLDs — #1 most abused
    "xyz","top","club","online","site","web","store","shop","info",
    "biz","icu","buzz","cyou","work","fun","life","live","news","world",
    "click","link","win","bid","download","stream","gdn","loan","racing",
    "review","science","trade","accountant","cricket","date","faith",
    "men","party","pw","review","space","website","accountant",
}


# TLDs that are restricted/verified (require institutional verification)
TRUSTED_TLDS = {"edu","gov","mil","ac","ac.uk","gov.uk","edu.au","gov.au"}

# Brand names for similarity checking
BRAND_NAMES = [
    "paypal","amazon","google","microsoft","apple","netflix","facebook",
    "twitter","instagram","linkedin","chase","wellsfargo","bankofamerica",
    "citibank","americanexpress","dropbox","docusign","ebay","youtube",
    "whatsapp","zoom","discord","spotify","adobe","salesforce","stripe",
    "coinbase","binance","kraken","robinhood","venmo","cashapp","zelle",
    "dhl","fedex","ups","usps","irs","dmv","medicare","socialsecurity",
]

# Suspicious words commonly appearing in phishing domains/paths
DIRTY_WORDS = [
    "verify","login","signin","secure","update","confirm","suspend",
    "unlock","restore","recover","validate","authenticate","authorize",
    "account","billing","payment","invoice","alert","warning","urgent",
    "limited","expire","suspended","blocked","unusual","activity",
    "customer","service","helpdesk","support","techsupport",
]


def extract_features(url: str) -> Dict[str, Any]:
    """Extract all 35 core features from a URL for ML classification."""
    try:
        parsed  = urllib.parse.urlparse(url)
        netloc  = parsed.netloc or ""
        host    = parsed.hostname or ""
        path    = parsed.path or ""
        query   = parsed.query or ""
        scheme  = parsed.scheme or ""
    except Exception:
        return _zero_features()

    # ── Parse domain parts ──
    parts   = _split_domain(host)
    domain  = parts["domain"]
    subdomain = parts["subdomain"]
    tld     = parts["tld"]
    fqdn    = host.lower()

    # ── Is IP? ──
    is_ip = _is_ip(host)

    # ── TLD features ──
    tld_low         = tld.lower()
    tld_phishing    = 1 if tld_low in PHISHING_TLDS else 0
    tld_legitimate  = 1 if tld_low in LEGIT_TLDS else 0
    tld_length      = len(tld)

    # ── Domain features ──
    domain_length   = len(domain)
    domain_in_top   = 1 if domain.lower() in TOP_DOMAINS else 0
    is_idn          = 1 if any(ord(c) > 127 for c in host) else 0  # Unicode homograph

    # ── Subdomain features ──
    sub_parts       = [p for p in subdomain.split(".") if p] if subdomain else []
    num_subdomains  = len(sub_parts)
    suspicious_sub  = int(any(w in subdomain.lower() for w in DIRTY_WORDS))

    # ── URL length features ──
    url_length      = len(url)
    path_length     = len(path)
    query_length    = len(query)

    # ── Character counts ──
    num_dots        = netloc.count(".")
    num_hyphens     = domain.count("-")
    num_underscores = url.count("_")
    num_slashes     = path.count("/")
    num_question    = url.count("?")
    num_equal       = url.count("=")
    num_at          = 1 if "@" in netloc else 0
    num_dollar      = url.count("$")
    num_excl        = url.count("!")
    num_ampersand   = url.count("&")
    num_digits_domain = sum(c.isdigit() for c in domain)
    digit_ratio_domain = num_digits_domain / max(len(domain), 1)
    num_letters_domain = sum(c.isalpha() for c in domain)
    letter_ratio_domain = num_letters_domain / max(len(domain), 1)

    # ── Entropy ──
    char_entropy    = _entropy(url)
    domain_entropy  = _entropy(domain)

    # ── Obfuscation ──
    encoded_chars   = re.findall(r"%[0-9a-fA-F]{2}", url)
    has_obfuscation = 1 if len(encoded_chars) > 2 or "@" in netloc or "//" in path else 0
    obfuscation_ratio = len(encoded_chars) / max(url_length, 1)
    num_obfuscated  = len(encoded_chars)

    # ── HTTPS ──
    is_https        = 1 if scheme == "https" else 0

    # ── Dirty words in URL ──
    url_lower       = url.lower()
    netloc_lower    = netloc.lower()
    num_dirty_url   = sum(1 for w in DIRTY_WORDS if w in url_lower)
    num_dirty_domain = sum(1 for w in DIRTY_WORDS if w in netloc_lower)

    # ── Brand similarity — key feature ──
    brand_sim_score = _brand_similarity(domain, subdomain, path, fqdn)

    # ── Path-based brand impersonation ──
    path_brand_impersonation = _path_brand_check(fqdn, path, query)

    # ── Special characters ratio in full URL ──
    special_chars   = re.findall(r"[~!$&'()*+,;=\[\]{}|\\^`]", url)
    special_ratio   = len(special_chars) / max(url_length, 1)

    # ── Port ──
    try:
        _port = parsed.port
        has_nonstandard_port = 1 if _port and _port not in (80, 443, 8080, 8443) else 0
    except ValueError:
        has_nonstandard_port = 0

    # ── Double slash in path ──
    has_double_slash = 1 if "//" in path else 0

    # ── URL-embedded brand domain (path impersonation) ──
    # e.g. http://evil.tk/www.paypal.com/login
    has_brand_in_path = path_brand_impersonation

    # ── Continuation rate (consecutive same chars) ──
    continuation_rate = _char_continuation_rate(url)

    return {
        # Identity
        "url_length":              url_length,
        "domain_length":           domain_length,
        "is_domain_ip":            int(is_ip),
        "tld_length":              tld_length,
        "tld_is_phishing":         tld_phishing,
        "tld_is_legitimate":       tld_legitimate,
        "is_https":                is_https,
        "is_idn":                  is_idn,
        # Structure
        "num_subdomains":          num_subdomains,
        "suspicious_subdomain":    suspicious_sub,
        "num_dots":                num_dots,
        "num_hyphens":             num_hyphens,
        "num_underscores":         num_underscores,
        "num_slashes":             num_slashes,
        "num_question_marks":      num_question,
        "num_equals":              num_equal,
        "num_at_symbols":          num_at,
        "num_dollar":              num_dollar,
        "num_ampersand":           num_ampersand,
        "num_obfuscated_chars":    num_obfuscated,
        "has_obfuscation":         has_obfuscation,
        "obfuscation_ratio":       round(obfuscation_ratio, 5),
        "has_nonstandard_port":    has_nonstandard_port,
        "has_double_slash":        has_double_slash,
        # Domain quality
        "domain_in_top_list":      domain_in_top,
        "digit_ratio_domain":      round(digit_ratio_domain, 4),
        "letter_ratio_domain":     round(letter_ratio_domain, 4),
        "num_digits_domain":       num_digits_domain,
        "domain_entropy":          round(domain_entropy, 4),
        # Similarity / content
        "brand_similarity_score":  round(brand_sim_score, 4),
        "has_brand_in_path":       has_brand_in_path,
        "num_dirty_words_url":     num_dirty_url,
        "num_dirty_words_domain":  num_dirty_domain,
        # Entropy / randomness
        "url_char_entropy":        round(char_entropy, 4),
        "char_continuation_rate":  round(continuation_rate, 4),
        "special_char_ratio":      round(special_ratio, 5),
        "path_length":             path_length,
        "query_length":            query_length,
    }


def _split_domain(host: str) -> Dict[str, str]:
    """Split host into subdomain, domain, tld."""
    MULTI = ["co.uk","co.in","com.au","co.nz","org.uk","net.uk",
             "ac.uk","gov.uk","co.za","com.br","co.jp","edu.au","gov.au"]
    h = host.lower()
    for m in MULTI:
        if h.endswith("."+m):
            rest  = h[:-(len(m)+1)]
            parts = rest.split(".")
            return {"subdomain": ".".join(parts[:-1]), "domain": parts[-1] if parts else "", "tld": m}
    parts = h.split(".")
    if len(parts) >= 2:
        return {"subdomain": ".".join(parts[:-2]), "domain": parts[-2], "tld": parts[-1]}
    return {"subdomain": "", "domain": h, "tld": ""}


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _entropy(s: str) -> float:
    if not s: return 0.0
    freq = {}
    for c in s: freq[c] = freq.get(c, 0) + 1
    return -sum((f/len(s)) * math.log2(f/len(s)) for f in freq.values())


def _brand_similarity(domain: str, subdomain: str, path: str, fqdn: str) -> float:
    """
    Returns 0.0–1.0 score of how similar this URL looks to a known brand.
    High score = more suspicious (domain resembles a brand but ISN'T the brand).
    """
    dom_low = domain.lower()
    full    = fqdn.lower()
    path_low = path.lower()

    for brand in BRAND_NAMES:
        # If this IS the real brand domain, score = 0 (not suspicious)
        if dom_low == brand:
            return 0.0
        # Exact brand in subdomain (e.g. paypal.evil.tk) = very suspicious
        sub_low = subdomain.lower()
        if brand in sub_low or brand in path_low:
            return 0.9
        # Leet speak: 0→o, 1→i/l, 3→e, 4→a
        leet = dom_low.translate(str.maketrans("013456@!","oieasgai"))
        if leet == brand or (len(brand) > 4 and brand in leet and dom_low != brand):
            return 0.95
        # Fuzzy: brand embedded in domain
        if len(brand) > 4 and brand in dom_low and dom_low != brand:
            return 0.8
        # Typosquat: edit distance 1 from brand
        if len(brand) > 5 and _edit_distance_1(dom_low, brand):
            return 0.85

    return 0.0


def _edit_distance_1(a: str, b: str) -> bool:
    """True if strings differ by exactly 1 character (sub/add/delete)."""
    if abs(len(a)-len(b)) > 1: return False
    if len(a) == len(b):
        diffs = sum(x!=y for x,y in zip(a,b))
        return diffs == 1
    # insertion/deletion
    shorter, longer = (a,b) if len(a)<len(b) else (b,a)
    i = j = diffs = 0
    while i < len(shorter) and j < len(longer):
        if shorter[i] != longer[j]:
            diffs += 1
            j += 1
        else:
            i += 1; j += 1
    return diffs <= 1


def _path_brand_check(fqdn: str, path: str, query: str) -> int:
    """
    Detect path-based brand impersonation.
    e.g. http://evil.tk/www.paypal.com/login  → 1
         https://mail.printakid.com/www.online.americanexpress.com/index.html → 1
    """
    combined = (path + "/" + query).lower()
    # Look for patterns like /www.brand.com/ or /brand.com/ in the path
    for brand in BRAND_NAMES:
        # Full domain in path: brand.com, www.brand.com
        patterns = [
            f"{brand}.com", f"{brand}.net", f"{brand}.org",
            f"www.{brand}", f"online.{brand}", f"secure.{brand}",
        ]
        for pat in patterns:
            if pat in combined:
                # Make sure the fqdn itself is NOT the brand
                if brand not in fqdn.replace("www.","").split(".")[0]:
                    return 1
    return 0


def _char_continuation_rate(url: str) -> float:
    """Ratio of consecutive repeated characters (common in DGA domains)."""
    if len(url) < 2: return 0.0
    continuations = sum(1 for i in range(1, len(url)) if url[i] == url[i-1])
    return continuations / (len(url) - 1)


def _zero_features() -> Dict[str, Any]:
    return {k: 0 for k in extract_features("https://example.com").keys()}


def feature_vector(url: str) -> list:
    """Return features as an ordered list for ML input."""
    f = extract_features(url)
    return list(f.values())


FEATURE_NAMES = list(extract_features("https://example.com").keys())
