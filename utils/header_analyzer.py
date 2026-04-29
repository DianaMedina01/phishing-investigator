import re


# Well-known brands that are commonly spoofed
SPOOFED_BRANDS = [
    "paypal", "amazon", "google", "apple", "microsoft", "netflix",
    "bank", "chase", "wellsfargo", "citibank", "irs", "fedex", "ups",
    "dhl", "usps", "ebay", "instagram", "facebook", "twitter", "linkedin",
]

# Typosquatting character substitutions
LOOKALIKE_SUBS = {
    "0": "o", "1": "l", "i": "l", "rn": "m", "vv": "w",
    "4": "a", "3": "e", "5": "s", "@": "a",
}


def analyze_headers(parsed):
    findings = []
    score_penalty = 0

    sender = parsed.get("sender", "")
    sender_domain = parsed.get("sender_domain", "")
    reply_to = parsed.get("reply_to", "")
    subject = parsed.get("subject", "")
    headers = parsed.get("headers", {})
    received_chain = parsed.get("received_chain", [])

    # --- 1. Sender domain spoofing / typosquatting ---
    spoofed_brand = _check_typosquatting(sender_domain)
    if spoofed_brand:
        findings.append({
            "category": "Sender Spoofing",
            "severity": "HIGH",
            "detail": f"Domain '{sender_domain}' appears to impersonate '{spoofed_brand}' via typosquatting.",
        })
        score_penalty += 35

    # --- 2. Reply-To mismatch ---
    if reply_to and sender:
        reply_domain = _extract_domain(reply_to)
        if reply_domain and reply_domain != sender_domain:
            findings.append({
                "category": "Reply-To Mismatch",
                "severity": "HIGH",
                "detail": f"Reply-To domain '{reply_domain}' differs from sender domain '{sender_domain}'. Replies would go to a different party.",
            })
            score_penalty += 25

    # --- 3. SPF / DKIM / DMARC in headers ---
    auth_results = headers.get("authentication-results", "") or headers.get("arc-authentication-results", "")
    if auth_results:
        if "spf=fail" in auth_results.lower():
            findings.append({
                "category": "SPF Fail",
                "severity": "HIGH",
                "detail": "SPF check failed — the sending server is not authorized to send on behalf of the claimed domain.",
            })
            score_penalty += 30
        elif "spf=softfail" in auth_results.lower():
            findings.append({
                "category": "SPF Soft Fail",
                "severity": "MEDIUM",
                "detail": "SPF soft fail — the sending server may not be authorized.",
            })
            score_penalty += 15
        elif "spf=pass" in auth_results.lower():
            findings.append({
                "category": "SPF Pass",
                "severity": "INFO",
                "detail": "SPF check passed.",
            })

        if "dkim=fail" in auth_results.lower():
            findings.append({
                "category": "DKIM Fail",
                "severity": "HIGH",
                "detail": "DKIM signature validation failed — email may have been tampered with in transit.",
            })
            score_penalty += 30
        elif "dkim=pass" in auth_results.lower():
            findings.append({
                "category": "DKIM Pass",
                "severity": "INFO",
                "detail": "DKIM signature is valid.",
            })

        if "dmarc=fail" in auth_results.lower():
            findings.append({
                "category": "DMARC Fail",
                "severity": "HIGH",
                "detail": "DMARC policy check failed — email failed both SPF and DKIM alignment.",
            })
            score_penalty += 25

    # --- 4. Received chain anomalies ---
    if received_chain:
        geo_hops = _extract_countries(received_chain)
        if len(geo_hops) >= 3:
            findings.append({
                "category": "Suspicious Routing",
                "severity": "MEDIUM",
                "detail": f"Email passed through {len(received_chain)} hops. Unusual routing can indicate obfuscation.",
            })
            score_penalty += 10

    # --- 5. Urgency in subject ---
    urgency_words = ["urgent", "verify", "suspended", "expire", "confirm", "action required",
                     "immediately", "warning", "alert", "limited time", "24 hours", "48 hours"]
    subject_lower = subject.lower()
    found_urgency = [w for w in urgency_words if w in subject_lower]
    if found_urgency:
        findings.append({
            "category": "Urgency Language in Subject",
            "severity": "MEDIUM",
            "detail": f"Subject contains urgency triggers: {', '.join(found_urgency)}. Common in phishing to pressure quick action.",
        })
        score_penalty += 15

    # --- 6. Free/suspicious sender TLDs ---
    suspicious_tlds = [".ru", ".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".click"]
    for tld in suspicious_tlds:
        if sender_domain.endswith(tld):
            findings.append({
                "category": "Suspicious Sender TLD",
                "severity": "MEDIUM",
                "detail": f"Sender domain uses TLD '{tld}', which is commonly associated with spam and phishing campaigns.",
            })
            score_penalty += 15
            break

    # --- 7. No headers at all (manual input only) ---
    if parsed.get("source") == "manual" and not headers and not auth_results:
        findings.append({
            "category": "No Headers Provided",
            "severity": "INFO",
            "detail": "No raw headers were provided. Paste email headers for deeper SPF/DKIM/routing analysis.",
        })

    return {
        "findings": findings,
        "score_penalty": min(score_penalty, 100),
    }


def _check_typosquatting(domain):
    if not domain:
        return None
    domain_clean = domain.split(".")[0].lower()
    # Normalize lookalike chars
    normalized = domain_clean
    for fake, real in LOOKALIKE_SUBS.items():
        normalized = normalized.replace(fake, real)
    for brand in SPOOFED_BRANDS:
        if brand in normalized and domain_clean != brand:
            return brand
        # Levenshtein-light: check if brand is substring after normalization
        if normalized == brand and domain_clean != brand:
            return brand
    return None


def _extract_domain(addr):
    match = re.search(r"@([\w.\-]+)", addr)
    return match.group(1).lower() if match else ""


def _extract_countries(received_chain):
    """Very rough country extraction from Received headers."""
    country_pattern = re.compile(r"\(.*?\[(\d+\.\d+\.\d+\.\d+)\].*?\)")
    ips = []
    for hop in received_chain:
        ips += country_pattern.findall(hop)
    return ips
