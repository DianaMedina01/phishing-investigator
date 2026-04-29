import re
import os
import hashlib
import requests
from urllib.parse import urlparse

PHISHTANK_API_KEY = os.environ.get("PHISHTANK_API_KEY", "")
PHISHTANK_URL = "https://checkurl.phishtank.com/checkurl/"

SUSPICIOUS_KEYWORDS = [
    "login", "verify", "secure", "account", "update", "confirm",
    "banking", "signin", "password", "credential", "wallet", "suspend",
    "restore", "validate", "unlock", "billing",
]

SUSPICIOUS_TLDS = [".ru", ".tk", ".ml", ".ga", ".cf", ".gq", ".xyz",
                   ".top", ".click", ".pw", ".win", ".party"]

URL_SHORTENERS = [
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "buff.ly",
    "short.link", "rebrand.ly", "cutt.ly", "is.gd",
]


def analyze_urls(urls):
    results = []
    score_penalty = 0

    for url in urls:
        entry = _analyze_single_url(url)
        results.append(entry)
        score_penalty += entry["penalty"]

    return {
        "results": results,
        "total_urls": len(urls),
        "score_penalty": min(score_penalty, 100),
    }


def _analyze_single_url(url):
    entry = {
        "url": url,
        "flags": [],
        "phishtank": None,
        "penalty": 0,
        "verdict": "unknown",
    }

    try:
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        path = parsed.path.lower()
        full = url.lower()
    except Exception:
        entry["flags"].append("Invalid URL format")
        entry["penalty"] = 10
        return entry

    # --- 1. HTTP (not HTTPS) ---
    if parsed.scheme == "http":
        entry["flags"].append("Uses HTTP (not HTTPS) — unencrypted connection")
        entry["penalty"] += 10

    # --- 2. IP address instead of domain ---
    if re.match(r"^\d+\.\d+\.\d+\.\d+", domain):
        entry["flags"].append("Uses raw IP address instead of domain name")
        entry["penalty"] += 25

    # --- 3. URL shortener ---
    for short in URL_SHORTENERS:
        if short in domain:
            entry["flags"].append(f"Uses URL shortener ({short}) — hides final destination")
            entry["penalty"] += 20
            break

    # --- 4. Suspicious keywords in path/domain ---
    found_keywords = [kw for kw in SUSPICIOUS_KEYWORDS if kw in full]
    if found_keywords:
        entry["flags"].append(f"Contains phishing keywords: {', '.join(found_keywords)}")
        entry["penalty"] += 15

    # --- 5. Suspicious TLD ---
    for tld in SUSPICIOUS_TLDS:
        if domain.endswith(tld):
            entry["flags"].append(f"Suspicious TLD: {tld}")
            entry["penalty"] += 15
            break

    # --- 6. Subdomain abuse (brand in subdomain) ---
    parts = domain.split(".")
    if len(parts) > 2:
        subdomain = ".".join(parts[:-2])
        brands = ["paypal", "apple", "google", "amazon", "microsoft", "netflix",
                  "bank", "chase", "irs", "fedex", "ups"]
        for brand in brands:
            if brand in subdomain:
                entry["flags"].append(
                    f"Brand name '{brand}' in subdomain — classic spoofing tactic"
                )
                entry["penalty"] += 30
                break

    # --- 7. Excessive subdomains ---
    if len(parts) > 4:
        entry["flags"].append(f"Unusually deep subdomain structure ({len(parts)} levels)")
        entry["penalty"] += 10

    # --- 8. Long URL with many query params ---
    if len(url) > 200:
        entry["flags"].append("Abnormally long URL (>200 chars) — may be obfuscating destination")
        entry["penalty"] += 10

    # --- 9. PhishTank lookup ---
    if PHISHTANK_API_KEY:
        pt_result = _check_phishtank(url)
        entry["phishtank"] = pt_result
        if pt_result and pt_result.get("in_database") and pt_result.get("verified"):
            entry["flags"].append("CONFIRMED phishing URL in PhishTank database")
            entry["penalty"] += 60

    # Verdict
    if entry["penalty"] >= 40:
        entry["verdict"] = "malicious"
    elif entry["penalty"] >= 15:
        entry["verdict"] = "suspicious"
    else:
        entry["verdict"] = "clean"

    entry["penalty"] = min(entry["penalty"], 100)
    return entry


def _check_phishtank(url):
    """
    Query the PhishTank API to check if a URL is a known phishing site.
    Requires PHISHTANK_API_KEY env var.
    """
    try:
        url_hash = hashlib.md5(url.encode("utf-8")).hexdigest()
        payload = {
            "url": url,
            "format": "json",
            "app_key": PHISHTANK_API_KEY,
        }
        r = requests.post(PHISHTANK_URL, data=payload, timeout=5,
                          headers={"User-Agent": "phishtank/phishing-investigator"})
        data = r.json()
        results = data.get("results", {})
        return {
            "in_database": results.get("in_database", False),
            "verified": results.get("verified", False),
            "phish_detail_url": results.get("phish_detail_url", ""),
        }
    except Exception as e:
        return {"error": str(e)}
