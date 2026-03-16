"""
SSL Certificate Inspector - Fixed: cert age no longer a standalone false-positive trigger
"""
import ssl, socket, urllib.parse
from datetime import datetime, timezone
from typing import Dict, Any

TRUSTED_CAs = ["digicert","globalsign","entrust","verisign","thawte","geotrust",
               "symantec","amazon","google trust","microsoft","sectigo","comodo",
               "incommon","usertrust","internet security research group","isrg"]


class SSLInspector:

    def inspect(self, url: str) -> Dict[str, Any]:
        parsed = urllib.parse.urlparse(url)
        hostname = parsed.hostname
        port = parsed.port or 443
        findings, score = [], 0
        cert_data = {}

        if parsed.scheme == "http":
            return {"module":"SSL Inspection","score":10,"findings_count":1,
                    "findings":[{"flagged":True,"check":"No SSL Certificate",
                                 "detail":"Site uses HTTP without encryption","severity":10}],
                    "certificate":None}

        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((hostname, port), timeout=8) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    cert_data = self._extract_cert_info(cert)

                    for chk in [
                        self._check_expiry(cert_data),
                        self._check_domain_match(cert, hostname),
                        self._check_issuer(cert_data),
                        # NOTE: cert age removed as standalone check — too many false positives
                        # (legitimate orgs renew certs regularly)
                    ]:
                        if chk.get("flagged"):
                            findings.append(chk)
                            score += chk.get("severity",0)
                        elif chk.get("check"):
                            findings.append(chk)

        except ssl.SSLCertVerificationError as e:
            findings.append({"flagged":True,"check":"SSL Verification Failed",
                             "detail":f"Certificate cannot be verified: {str(e)[:80]}","severity":30})
            score += 30
        except ssl.SSLError as e:
            findings.append({"flagged":True,"check":"SSL Error",
                             "detail":f"SSL handshake error: {str(e)[:80]}","severity":25})
            score += 25
        except (socket.timeout, ConnectionRefusedError, OSError) as e:
            findings.append({"flagged":False,"check":"SSL Connection",
                             "detail":f"Could not connect: {str(e)[:60]}","severity":0})
        except Exception as e:
            findings.append({"flagged":True,"check":"Certificate Issue",
                             "detail":f"Possible self-signed cert: {str(e)[:80]}","severity":25})
            score += 25

        return {"module":"SSL Inspection","score":min(score,100),
                "findings_count":len([f for f in findings if f.get("flagged")]),
                "findings":findings,"certificate":cert_data or None}

    def _extract_cert_info(self, cert):
        def parse_dt(s):
            try: return datetime.strptime(s, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
            except: return None

        issuer = {k:v for item in cert.get("issuer",[]) for k,v in item}
        subject = {k:v for item in cert.get("subject",[]) for k,v in item}
        nb = parse_dt(cert.get("notBefore",""))
        na = parse_dt(cert.get("notAfter",""))
        san = [name for typ,name in cert.get("subjectAltName",[]) if typ=="DNS"]

        # Store datetimes separately for internal checks — NOT in the returned dict
        self._cert_nb = nb
        self._cert_na = na
        return {
            "subject":    subject.get("commonName", "unknown"),
            "issuer_cn":  issuer.get("commonName", "unknown"),
            "issuer_org":  issuer.get("organizationName", "unknown"),
            "valid_from":  nb.isoformat() if nb else None,
            "valid_until": na.isoformat() if na else None,
            "san_domains": san,
        }

    def _check_expiry(self, d):
        na = getattr(self, "_cert_na", None)
        if not na: return {"flagged":False,"check":"Certificate Expiry","severity":0}
        days = (na - datetime.now(timezone.utc)).days
        if days < 0:
            return {"flagged":True,"check":"Expired Certificate",
                    "detail":f"Certificate expired {abs(days)} days ago","severity":35}
        if days < 7:
            return {"flagged":True,"check":"Certificate Expiring Very Soon",
                    "detail":f"Expires in {days} days","severity":20}
        if days < 30:
            return {"flagged":True,"check":"Certificate Expiring Soon",
                    "detail":f"Expires in {days} days","severity":10}
        return {"flagged":False,"check":"Certificate Expiry",
                "detail":f"Valid for {days} more days","severity":0}

    def _check_domain_match(self, cert, hostname):
        san = [n for t,n in cert.get("subjectAltName",[]) if t=="DNS"]
        cn = {k:v for item in cert.get("subject",[]) for k,v in item}.get("commonName","")
        for name in san + [cn]:
            name = (name or "").lower().strip()
            if name == hostname.lower():
                return {"flagged":False,"check":"Domain Match","severity":0}
            if name.startswith("*."):
                parts = hostname.lower().split(".")
                if len(parts) >= 2 and ".".join(parts[1:]) == name[2:]:
                    return {"flagged":False,"check":"Domain Match (Wildcard)","severity":0}
        return {"flagged":True,"check":"Certificate Domain Mismatch",
                "detail":f"Certificate is for '{cn}', not '{hostname}'","severity":30}

    def _check_issuer(self, d):
        issuer = (d.get("issuer_org") or d.get("issuer_cn") or "").lower()
        for t in TRUSTED_CAs:
            if t in issuer:
                return {"flagged":False,"check":"Certificate Issuer",
                        "detail":f"Issued by trusted CA: {d.get('issuer_org')}","severity":0}
        if "let" in issuer and "encrypt" in issuer:
            # Let's Encrypt alone is NOT enough to flag — it's used by millions of legit sites
            return {"flagged":False,"check":"Certificate Issuer",
                    "detail":"Issued by Let's Encrypt (widely used, legitimate CA)","severity":0}
        if not issuer or issuer in ["unknown",""]:
            return {"flagged":True,"check":"Unknown Certificate Issuer",
                    "detail":"Cannot identify CA — possible self-signed certificate","severity":25}
        return {"flagged":False,"check":"Certificate Issuer",
                "detail":f"Issued by: {d.get('issuer_org','Unknown')}","severity":0}

    def _strip_internal(self, cert_data):
        if cert_data:
            cert_data.pop("_nb", None)
            cert_data.pop("_na", None)
        return cert_data
