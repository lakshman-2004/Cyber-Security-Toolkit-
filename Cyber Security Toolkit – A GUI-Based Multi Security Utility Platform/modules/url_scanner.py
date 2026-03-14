"""
Module 4: URL Security Scanner
Detect phishing or suspicious URLs without external API keys.
"""

import re
import socket
import urllib.parse
from typing import Optional

# Optional - gracefully degrade if requests is not installed
try:
    import requests
    _REQUESTS_AVAILABLE = True
except ImportError:
    _REQUESTS_AVAILABLE = False


# -- Suspicious keyword lists --------------------------------------------------

_PHISHING_KEYWORDS = [
    "login", "signin", "sign-in", "verify", "verification", "secure",
    "account", "update", "confirm", "banking", "paypal", "ebay", "amazon",
    "apple", "google", "microsoft", "netflix", "facebook", "instagram",
    "password", "credential", "wallet", "crypto", "bitcoin", "support",
    "helpdesk", "alert", "urgent", "suspended", "limited", "unusual",
    "activity", "click", "free", "prize", "winner", "congratulations",
]

_SUSPICIOUS_TLDS = {
    ".xyz", ".tk", ".ml", ".ga", ".cf", ".gq", ".pw", ".top",
    ".click", ".link", ".download", ".zip", ".review", ".country",
    ".kim", ".science", ".work", ".party", ".gdn", ".stream",
    ".bid", ".loan", ".win", ".racing", ".date", ".faith",
}

_SAFE_TLDS = {".com", ".org", ".net", ".edu", ".gov", ".io", ".co"}

_URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "adf.ly", "shorte.st", "clck.ru", "cutt.ly",
}


# -- Main scanner function -----------------------------------------------------

def scan_url(url: str) -> dict:
    """
    Analyse a URL for security risks.

    Returns:
        {
            "url":          str,
            "risk_level":   "LOW" | "MEDIUM" | "HIGH" | "CRITICAL",
            "risk_color":   hex str,
            "risk_score":   int  (0-100),
            "checks":       dict  (check_name -> bool),
            "reasons":      list[str],
            "suggestions":  list[str],
            "domain":       str,
            "scheme":       str,
            "ip_address":   str | None,
            "redirected_to": str | None,
            "success":      bool,
            "error":        str | None,
        }
    """
    url = url.strip()
    if not url:
        return _error_result(url, "URL cannot be empty.")

    # Normalise - add scheme if missing
    if not re.match(r"^https?://", url, re.IGNORECASE):
        url = "http://" + url

    try:
        parsed = urllib.parse.urlparse(url)
    except Exception as exc:
        return _error_result(url, f"URL parse error: {exc}")

    domain = parsed.netloc.lower().split(":")[0]   # strip port
    scheme = parsed.scheme.lower()
    path   = parsed.path.lower()
    full   = url.lower()

    checks = {}
    reasons = []
    suggestions = []
    risk_score = 0

    # 1. HTTPS check
    checks["has_https"] = scheme == "https"
    if not checks["has_https"]:
        risk_score += 20
        reasons.append("No HTTPS - connection is not encrypted.")
        suggestions.append("Prefer URLs that start with https://")

    # 2. IP address as host
    checks["uses_ip"] = _is_ip(domain)
    if checks["uses_ip"]:
        risk_score += 25
        reasons.append("URL uses a raw IP address instead of a domain name.")
        suggestions.append("Legitimate sites use domain names, not bare IP addresses.")

    # 3. Suspicious TLD
    tld = _get_tld(domain)
    checks["suspicious_tld"] = tld in _SUSPICIOUS_TLDS
    if checks["suspicious_tld"]:
        risk_score += 20
        reasons.append(f"Suspicious top-level domain: '{tld}'")
        suggestions.append("Be cautious with uncommon TLDs often used in phishing.")

    # 4. URL shortener
    checks["is_shortener"] = any(s in domain for s in _URL_SHORTENERS)
    if checks["is_shortener"]:
        risk_score += 15
        reasons.append("URL uses a link-shortening service - destination is hidden.")
        suggestions.append("Expand shortened URLs before clicking them.")

    # 5. Phishing keywords in domain / path
    kw_hits = [kw for kw in _PHISHING_KEYWORDS if kw in full]
    checks["has_phishing_keywords"] = len(kw_hits) > 0
    if checks["has_phishing_keywords"]:
        hit_str = ", ".join(kw_hits[:5])
        risk_score += min(len(kw_hits) * 8, 30)
        reasons.append(f"Suspicious keywords detected: {hit_str}")
        suggestions.append("Phishing pages often mimic trusted brands in their URL.")

    # 6. Excessive subdomains
    subdomain_count = len(domain.split(".")) - 2
    checks["many_subdomains"] = subdomain_count >= 3
    if checks["many_subdomains"]:
        risk_score += 10
        reasons.append(f"Unusually many subdomains ({subdomain_count}) - possible spoofing.")

    # 7. Long domain
    checks["long_domain"] = len(domain) > 50
    if checks["long_domain"]:
        risk_score += 10
        reasons.append(f"Very long domain name ({len(domain)} chars) - common in phishing.")

    # 8. Hyphens in domain
    hyphen_count = domain.count("-")
    checks["many_hyphens"] = hyphen_count >= 3
    if checks["many_hyphens"]:
        risk_score += 10
        reasons.append(f"Domain contains {hyphen_count} hyphens - often used to mimic real sites.")

    # 9. Special characters / encoded chars
    checks["has_encoded_chars"] = "%" in url
    if checks["has_encoded_chars"]:
        risk_score += 10
        reasons.append("URL contains percent-encoded characters - possible obfuscation.")

    # 10. Double slash in path (redirect trick)
    checks["double_slash_path"] = "//" in path
    if checks["double_slash_path"]:
        risk_score += 10
        reasons.append("Double slash in path - possible open-redirect trick.")

    # 11. @ symbol in URL (credential embedding)
    checks["has_at_symbol"] = "@" in parsed.netloc
    if checks["has_at_symbol"]:
        risk_score += 20
        reasons.append("'@' symbol in URL - browser ignores everything before it (credential trick).")

    # 12. DNS resolution
    ip_address = _resolve_domain(domain)
    checks["dns_resolves"] = ip_address is not None
    if not checks["dns_resolves"] and not checks["uses_ip"]:
        risk_score += 15
        reasons.append("Domain does not resolve - may be inactive or fake.")

    # 13. HTTP redirect check (optional - needs requests)
    redirected_to = None
    if _REQUESTS_AVAILABLE:
        redirected_to, redirect_risk = _check_redirect(url)
        checks["suspicious_redirect"] = redirect_risk
        if redirect_risk:
            risk_score += 15
            reasons.append("URL redirects to a different domain - possible phishing redirect.")

    # Clamp score
    risk_score = max(0, min(risk_score, 100))

    # Risk level
    if risk_score < 20:
        risk_level, risk_color = "LOW",      "#2ecc71"
    elif risk_score < 45:
        risk_level, risk_color = "MEDIUM",   "#f1c40f"
    elif risk_score < 70:
        risk_level, risk_color = "HIGH",     "#e67e22"
    else:
        risk_level, risk_color = "CRITICAL", "#e74c3c"

    if not reasons:
        reasons.append("No obvious threats detected.")
        suggestions.append("Always verify the site owner before entering sensitive data.")

    return {
        "url":              url,
        "risk_level":       risk_level,
        "risk_color":       risk_color,
        "risk_score":       risk_score,
        "checks":           checks,
        "reasons":          reasons,
        "suggestions":      suggestions,
        "domain":           domain,
        "scheme":           scheme,
        "ip_address":       ip_address,
        "redirected_to":    redirected_to,
        "success":          True,
        "error":            None,
    }


# -- helpers -------------------------------------------------------------------

def _is_ip(host: str) -> bool:
    """Return True if host looks like an IPv4 or IPv6 address."""
    try:
        socket.inet_pton(socket.AF_INET, host)
        return True
    except OSError:
        pass
    try:
        socket.inet_pton(socket.AF_INET6, host)
        return True
    except OSError:
        pass
    return False


def _get_tld(domain: str) -> str:
    parts = domain.split(".")
    return "." + parts[-1] if parts else ""


def _resolve_domain(domain: str) -> Optional[str]:
    try:
        return socket.gethostbyname(domain)
    except Exception:
        return None


def _check_redirect(url: str):
    """
    Follow redirects and return (final_url, is_suspicious).
    is_suspicious = True if the final domain differs from the original.
    """
    try:
        resp = requests.get(
            url,
            allow_redirects=True,
            timeout=5,
            headers={"User-Agent": "Mozilla/5.0"},
            verify=False,
        )
        final_url = resp.url
        orig_domain = urllib.parse.urlparse(url).netloc.lower()
        final_domain = urllib.parse.urlparse(final_url).netloc.lower()
        suspicious = (orig_domain != final_domain) and bool(final_domain)
        return final_url if suspicious else None, suspicious
    except Exception:
        return None, False
