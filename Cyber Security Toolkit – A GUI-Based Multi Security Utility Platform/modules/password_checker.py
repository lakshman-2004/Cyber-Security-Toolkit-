"""
Module 2: Password Strength Checker
Checks password strength based on length, complexity, and character variety.
"""

import re


def check_password_strength(password: str) -> dict:
    """
    Analyse a password and return a detailed strength report.

    Returns a dict with keys:
        score       - int 0-100
        level       - str  "Very Weak" | "Weak" | "Medium" | "Strong" | "Very Strong"
        color       - hex colour string matching the level
        checks      - dict of individual check results (bool)
        suggestions - list of improvement tips
        entropy     - approximate bit-entropy (float)
    """
    checks = {
        "length_8":       len(password) >= 8,
        "length_12":      len(password) >= 12,
        "length_16":      len(password) >= 16,
        "has_lowercase":  bool(re.search(r"[a-z]", password)),
        "has_uppercase":  bool(re.search(r"[A-Z]", password)),
        "has_digit":      bool(re.search(r"\d", password)),
        "has_special":    bool(re.search(r"[!@#$%^&*()\-_=+\[\]{};:'\",.<>?/\\|`~]", password)),
        "no_spaces":      " " not in password,
        "no_repeat":      not bool(re.search(r"(.)\1{2,}", password)),   # no char repeated 3+ times
        "no_common":      _not_common(password),
    }

    # --- scoring ---
    score = 0
    if checks["length_8"]:   score += 10
    if checks["length_12"]:  score += 10
    if checks["length_16"]:  score += 10
    if checks["has_lowercase"]: score += 10
    if checks["has_uppercase"]: score += 15
    if checks["has_digit"]:     score += 15
    if checks["has_special"]:   score += 20
    if checks["no_spaces"]:     score += 5
    if checks["no_repeat"]:     score += 5
    if checks["no_common"]:     score += 10

    # Clamp
    score = max(0, min(score, 100))

    # --- level & colour ---
    if score < 20:
        level, color = "Very Weak",  "#e74c3c"
    elif score < 40:
        level, color = "Weak",       "#e67e22"
    elif score < 60:
        level, color = "Medium",     "#f1c40f"
    elif score < 80:
        level, color = "Strong",     "#2ecc71"
    else:
        level, color = "Very Strong","#27ae60"

    # --- suggestions ---
    suggestions = []
    if not checks["length_8"]:
        suggestions.append("Use at least 8 characters.")
    elif not checks["length_12"]:
        suggestions.append("Increase length to 12+ characters for better security.")
    elif not checks["length_16"]:
        suggestions.append("Consider using 16+ characters for maximum security.")
    if not checks["has_lowercase"]:
        suggestions.append("Add lowercase letters (a-z).")
    if not checks["has_uppercase"]:
        suggestions.append("Add uppercase letters (A-Z).")
    if not checks["has_digit"]:
        suggestions.append("Include at least one number (0-9).")
    if not checks["has_special"]:
        suggestions.append("Add special characters (e.g. @, #, $, !).")
    if not checks["no_repeat"]:
        suggestions.append("Avoid repeating the same character 3 or more times.")
    if not checks["no_common"]:
        suggestions.append("Avoid common passwords like 'password', '123456', etc.")
    if not suggestions:
        suggestions.append("Great password! Keep it safe and never reuse it.")

    # --- entropy estimate ---
    charset = 0
    if checks["has_lowercase"]: charset += 26
    if checks["has_uppercase"]: charset += 26
    if checks["has_digit"]:     charset += 10
    if checks["has_special"]:   charset += 32
    if charset == 0:            charset = 1
    import math
    entropy = round(len(password) * math.log2(charset), 1)

    return {
        "score":       score,
        "level":       level,
        "color":       color,
        "checks":      checks,
        "suggestions": suggestions,
        "entropy":     entropy,
    }


# -- helpers ------------------------------------------------------------------

_COMMON_PASSWORDS = {
    "password", "123456", "12345678", "qwerty", "abc123", "monkey",
    "1234567", "letmein", "trustno1", "dragon", "baseball", "iloveyou",
    "master", "sunshine", "ashley", "bailey", "passw0rd", "shadow",
    "123123", "654321", "superman", "qazwsx", "michael", "football",
    "password1", "password123", "admin", "welcome", "login", "hello",
    "charlie", "donald", "password2", "qwerty123", "1q2w3e4r",
}


def _not_common(password: str) -> bool:
    return password.lower() not in _COMMON_PASSWORDS
