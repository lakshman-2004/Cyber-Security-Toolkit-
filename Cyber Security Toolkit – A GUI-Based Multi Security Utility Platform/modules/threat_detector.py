"""
Bonus Module: AI Threat Detection Dashboard
Aggregates results from all modules and produces an overall threat assessment.
"""

from modules.password_checker import check_password_strength
from modules.url_scanner import scan_url


# -- Threat levels -------------------------------------------------------------

THREAT_LEVELS = {
    "NONE":     {"label": "None",     "color": "#2ecc71", "icon": "OK"},
    "LOW":      {"label": "Low",      "color": "#27ae60", "icon": "LOW"},
    "MEDIUM":   {"label": "Medium",   "color": "#f1c40f", "icon": "MED"},
    "HIGH":     {"label": "High",     "color": "#e67e22", "icon": "HIGH"},
    "CRITICAL": {"label": "Critical", "color": "#e74c3c", "icon": "CRIT"},
}


def analyse_threats(
    open_ports: list = None,
    password: str = None,
    url: str = None,
    extra_findings: list = None,
) -> dict:
    """
    Aggregate threat findings from multiple modules.

    Parameters
    ----------
    open_ports      : list of int  - open ports found by the port scanner
    password        : str          - password to evaluate
    url             : str          - URL to evaluate
    extra_findings  : list of str  - any additional free-text findings

    Returns
    -------
    {
        "threat_level":  str,
        "threat_color":  str,
        "threat_icon":   str,
        "threat_score":  int  (0-100),
        "findings":      list[dict],   # {category, severity, message, recommendation}
        "summary":       str,
    }
    """
    findings = []
    total_score = 0

    # -- 1. Port scan findings -------------------------------------------------
    if open_ports:
        _DANGEROUS_PORTS = {
            21:    ("FTP",              "HIGH",   "FTP transmits data in plaintext."),
            23:    ("Telnet",           "CRITICAL","Telnet is unencrypted - use SSH instead."),
            445:   ("SMB",             "HIGH",   "SMB is frequently exploited (EternalBlue)."),
            3389:  ("RDP",             "HIGH",   "RDP exposed to internet is a common attack vector."),
            4444:  ("Metasploit",      "CRITICAL","Port 4444 is the default Metasploit listener."),
            1433:  ("MS SQL Server",   "HIGH",   "Database port exposed - restrict access."),
            3306:  ("MySQL",           "HIGH",   "Database port exposed - restrict access."),
            5432:  ("PostgreSQL",      "HIGH",   "Database port exposed - restrict access."),
            27017: ("MongoDB",         "HIGH",   "MongoDB port exposed - restrict access."),
            6379:  ("Redis",           "HIGH",   "Redis port exposed - often unauthenticated."),
            5900:  ("VNC",             "HIGH",   "VNC exposed - remote desktop risk."),
            2375:  ("Docker",          "CRITICAL","Docker daemon exposed without TLS."),
            8080:  ("HTTP Proxy",      "MEDIUM", "HTTP proxy port open - verify it's intentional."),
            8888:  ("Jupyter Notebook","HIGH",   "Jupyter Notebook may allow arbitrary code execution."),
        }
        _NOTABLE_PORTS = {
            22:  ("SSH",   "LOW",    "SSH open - ensure key-based auth and disable root login."),
            80:  ("HTTP",  "LOW",    "HTTP open - consider redirecting to HTTPS."),
            443: ("HTTPS", "NONE",   "HTTPS open - good practice."),
            25:  ("SMTP",  "MEDIUM", "SMTP open - verify mail relay is not open."),
            53:  ("DNS",   "MEDIUM", "DNS open - verify it's not an open resolver."),
        }

        for port in open_ports:
            if port in _DANGEROUS_PORTS:
                svc, sev, msg = _DANGEROUS_PORTS[port]
                findings.append({
                    "category":       "Port Scanner",
                    "severity":       sev,
                    "message":        f"Port {port} ({svc}) is open.",
                    "recommendation": msg,
                })
                total_score += _severity_score(sev)
            elif port in _NOTABLE_PORTS:
                svc, sev, msg = _NOTABLE_PORTS[port]
                if sev != "NONE":
                    findings.append({
                        "category":       "Port Scanner",
                        "severity":       sev,
                        "message":        f"Port {port} ({svc}) is open.",
                        "recommendation": msg,
                    })
                    total_score += _severity_score(sev)

        if len(open_ports) > 20:
            findings.append({
                "category":       "Port Scanner",
                "severity":       "HIGH",
                "message":        f"{len(open_ports)} open ports detected - large attack surface.",
                "recommendation": "Close unnecessary ports and use a firewall.",
            })
            total_score += 20

    # -- 2. Password findings --------------------------------------------------
    if password:
        result = check_password_strength(password)
        level  = result["level"]
        score  = result["score"]

        if level in ("Very Weak", "Weak"):
            sev = "HIGH" if level == "Very Weak" else "MEDIUM"
            findings.append({
                "category":       "Password Checker",
                "severity":       sev,
                "message":        f"Password strength: {level} (score {score}/100).",
                "recommendation": " | ".join(result["suggestions"]),
            })
            total_score += _severity_score(sev)
        elif level == "Medium":
            findings.append({
                "category":       "Password Checker",
                "severity":       "LOW",
                "message":        f"Password strength: Medium (score {score}/100).",
                "recommendation": " | ".join(result["suggestions"]),
            })
            total_score += 5

    # -- 3. URL findings -------------------------------------------------------
    if url:
        result = scan_url(url)
        url_risk = result["risk_level"]
        if url_risk in ("HIGH", "CRITICAL"):
            sev = url_risk
            findings.append({
                "category":       "URL Scanner",
                "severity":       sev,
                "message":        f"URL risk level: {url_risk} (score {result['risk_score']}/100).",
                "recommendation": " | ".join(result["reasons"][:3]),
            })
            total_score += _severity_score(sev)
        elif url_risk == "MEDIUM":
            findings.append({
                "category":       "URL Scanner",
                "severity":       "MEDIUM",
                "message":        f"URL risk level: MEDIUM (score {result['risk_score']}/100).",
                "recommendation": " | ".join(result["reasons"][:2]),
            })
            total_score += 15

    # -- 4. Extra findings -----------------------------------------------------
    if extra_findings:
        for item in extra_findings:
            findings.append({
                "category":       "Manual",
                "severity":       "MEDIUM",
                "message":        str(item),
                "recommendation": "Review and address this finding.",
            })
            total_score += 10

    # -- Aggregate -------------------------------------------------------------
    total_score = max(0, min(total_score, 100))

    if total_score == 0:
        level_key = "NONE"
    elif total_score < 20:
        level_key = "LOW"
    elif total_score < 45:
        level_key = "MEDIUM"
    elif total_score < 70:
        level_key = "HIGH"
    else:
        level_key = "CRITICAL"

    level_info = THREAT_LEVELS[level_key]

    if not findings:
        summary = "No threats detected. System appears secure based on the provided inputs."
    else:
        critical = sum(1 for f in findings if f["severity"] == "CRITICAL")
        high     = sum(1 for f in findings if f["severity"] == "HIGH")
        medium   = sum(1 for f in findings if f["severity"] == "MEDIUM")
        low      = sum(1 for f in findings if f["severity"] == "LOW")
        parts = []
        if critical: parts.append(f"{critical} critical")
        if high:     parts.append(f"{high} high")
        if medium:   parts.append(f"{medium} medium")
        if low:      parts.append(f"{low} low")
        summary = (
            f"Threat level: {level_info['label']}. "
            f"Found {len(findings)} issue(s): {', '.join(parts)}. "
            "Review findings and apply recommendations."
        )

    return {
        "threat_level": level_key,
        "threat_color": level_info["color"],
        "threat_icon":  level_info["icon"],
        "threat_score": total_score,
        "findings":     findings,
        "summary":      summary,
    }


# -- helpers -------------------------------------------------------------------

def _severity_score(severity: str) -> int:
    return {"NONE": 0, "LOW": 5, "MEDIUM": 15, "HIGH": 25, "CRITICAL": 35}.get(severity, 0)
