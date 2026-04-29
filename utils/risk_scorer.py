import re


URGENCY_PHRASES = [
    "act now", "immediate action", "account suspended", "verify immediately",
    "urgent", "within 24 hours", "within 48 hours", "click here now",
    "your account will be", "limited time", "expire", "permanently closed",
    "frozen", "security alert", "unauthorized access", "confirm your identity",
]

CREDENTIAL_PHRASES = [
    "enter your password", "enter your username", "social security",
    "credit card", "bank account", "date of birth", "mother's maiden",
    "ssn", "routing number", "pin number",
]

IMPERSONATION_BRANDS = [
    "paypal", "amazon", "apple", "google", "microsoft", "netflix",
    "irs", "fedex", "ups", "dhl", "usps", "chase", "bank of america",
    "wells fargo", "citibank",
]


def score_email(parsed, header_report, url_report):
    body = parsed.get("body", "").lower()
    subject = parsed.get("subject", "").lower()
    sender = parsed.get("sender", "").lower()

    base_score = 0
    signals = []

    # --- Header penalty ---
    header_penalty = header_report.get("score_penalty", 0)
    if header_penalty > 0:
        base_score += header_penalty
        signals.append({
            "source": "Headers",
            "weight": header_penalty,
            "detail": f"{len(header_report.get('findings', []))} header issue(s) found",
        })

    # --- URL penalty ---
    url_penalty = url_report.get("score_penalty", 0)
    malicious_urls = sum(1 for u in url_report.get("results", []) if u["verdict"] == "malicious")
    suspicious_urls = sum(1 for u in url_report.get("results", []) if u["verdict"] == "suspicious")
    if url_penalty > 0:
        base_score += min(url_penalty, 40)  # cap URL contribution
        signals.append({
            "source": "URLs",
            "weight": min(url_penalty, 40),
            "detail": f"{malicious_urls} malicious, {suspicious_urls} suspicious URL(s)",
        })

    # --- Urgency in body ---
    urgency_hits = [p for p in URGENCY_PHRASES if p in body or p in subject]
    if urgency_hits:
        penalty = min(len(urgency_hits) * 8, 25)
        base_score += penalty
        signals.append({
            "source": "Urgency Language",
            "weight": penalty,
            "detail": f"Phrases detected: {', '.join(urgency_hits[:3])}{'...' if len(urgency_hits) > 3 else ''}",
        })

    # --- Credential harvesting language ---
    cred_hits = [p for p in CREDENTIAL_PHRASES if p in body]
    if cred_hits:
        penalty = min(len(cred_hits) * 12, 30)
        base_score += penalty
        signals.append({
            "source": "Credential Harvesting",
            "weight": penalty,
            "detail": f"Sensitive data requested: {', '.join(cred_hits[:3])}",
        })

    # --- Brand impersonation in body ---
    impersonated = [b for b in IMPERSONATION_BRANDS if b in body or b in sender]
    if impersonated and parsed.get("sender_domain"):
        domain = parsed["sender_domain"]
        for brand in impersonated:
            if brand not in domain:
                penalty = 20
                base_score += penalty
                signals.append({
                    "source": "Brand Impersonation",
                    "weight": penalty,
                    "detail": f"Email mentions '{brand}' but sender domain is '{domain}'",
                })
                break

    # --- Grammar / poor formatting heuristic ---
    grammar_score = _check_grammar(body)
    if grammar_score > 0:
        base_score += grammar_score
        signals.append({
            "source": "Poor Grammar/Formatting",
            "weight": grammar_score,
            "detail": "Unusual capitalization, spacing, or punctuation patterns detected",
        })

    # --- Attachments ---
    if parsed.get("has_attachments"):
        base_score += 10
        signals.append({
            "source": "Attachments",
            "weight": 10,
            "detail": "Email contains attachments — could be malware delivery",
        })

    # --- Final score and verdict ---
    final_score = min(base_score, 100)

    if final_score >= 65:
        verdict = "PHISHING"
        verdict_label = "High probability phishing"
    elif final_score >= 35:
        verdict = "SUSPICIOUS"
        verdict_label = "Suspicious — treat with caution"
    else:
        verdict = "LIKELY_SAFE"
        verdict_label = "No major red flags detected"

    return {
        "risk_score": final_score,
        "verdict": verdict,
        "verdict_label": verdict_label,
        "signals": signals,
        "header_findings": header_report.get("findings", []),
        "url_results": url_report.get("results", []),
    }


def _check_grammar(text):
    if not text or len(text) < 50:
        return 0
    penalty = 0
    # Multiple exclamation marks
    if text.count("!") > 3:
        penalty += 5
    # ALL CAPS words (excluding short words)
    caps_words = re.findall(r"\b[A-Z]{4,}\b", text)
    if len(caps_words) > 3:
        penalty += 5
    # Dear + generic salutation
    if re.search(r"\bdear (valued |customer|user|member|account holder)", text.lower()):
        penalty += 5
    return min(penalty, 15)
