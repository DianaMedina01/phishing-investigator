import email
import email.parser
import re
from email.header import decode_header


def _decode_str(value):
    """Decode RFC2047-encoded header strings."""
    if not value:
        return ""
    parts = decode_header(value)
    decoded = []
    for part, charset in parts:
        if isinstance(part, bytes):
            decoded.append(part.decode(charset or "utf-8", errors="replace"))
        else:
            decoded.append(part)
    return " ".join(decoded)


def extract_urls(text):
    """Extract all URLs from a text block."""
    pattern = r'https?://[^\s<>"\')\]|]+'
    return list(set(re.findall(pattern, text)))


def parse_email(raw=None, sender="", subject="", body="", raw_headers="", links=""):
    """
    Parse an email from raw .eml content or from individual fields.
    Returns a normalized dict for downstream analyzers.
    """
    result = {
        "sender": "",
        "sender_domain": "",
        "reply_to": "",
        "subject": "",
        "body": "",
        "headers": {},
        "received_chain": [],
        "urls": [],
        "has_attachments": False,
        "source": "manual",
    }

    if raw:
        result["source"] = "eml"
        parser = email.parser.Parser()
        msg = parser.parsestr(raw)

        result["sender"] = _decode_str(msg.get("From", ""))
        result["reply_to"] = _decode_str(msg.get("Reply-To", ""))
        result["subject"] = _decode_str(msg.get("Subject", ""))
        result["headers"] = dict(msg.items())
        result["received_chain"] = msg.get_all("Received") or []

        # Extract body
        if msg.is_multipart():
            for part in msg.walk():
                ctype = part.get_content_type()
                disp = str(part.get("Content-Disposition", ""))
                if "attachment" in disp:
                    result["has_attachments"] = True
                if ctype == "text/plain" and "attachment" not in disp:
                    charset = part.get_content_charset() or "utf-8"
                    result["body"] += part.get_payload(decode=True).decode(
                        charset, errors="replace"
                    )
                elif ctype == "text/html" and "attachment" not in disp:
                    charset = part.get_content_charset() or "utf-8"
                    html = part.get_payload(decode=True).decode(
                        charset, errors="replace"
                    )
                    # Strip HTML tags for body text, extract URLs from HTML
                    result["urls"] += extract_urls(html)
                    result["body"] += re.sub(r"<[^>]+>", " ", html)
        else:
            charset = msg.get_content_charset() or "utf-8"
            payload = msg.get_payload(decode=True)
            if payload:
                result["body"] = payload.decode(charset, errors="replace")

    else:
        # Manual input
        result["sender"] = sender.strip()
        result["subject"] = subject.strip()
        result["body"] = body.strip()
        result["headers"] = _parse_raw_headers(raw_headers)
        result["received_chain"] = [
            v for k, v in result["headers"].items() if k.lower() == "received"
        ]
        # Links field: comma or newline separated
        if links:
            manual_links = [l.strip() for l in re.split(r"[,\n]", links) if l.strip()]
            result["urls"] += manual_links

    # Always extract URLs from body too
    result["urls"] += extract_urls(result["body"])
    result["urls"] = list(set(result["urls"]))

    # Extract sender domain
    match = re.search(r"@([\w.\-]+)", result["sender"])
    result["sender_domain"] = match.group(1).lower() if match else ""

    return result


def _parse_raw_headers(raw):
    """Parse a pasted block of email headers into a dict."""
    headers = {}
    if not raw:
        return headers
    current_key = None
    for line in raw.splitlines():
        if line and line[0] in (" ", "\t") and current_key:
            headers[current_key] += " " + line.strip()
        elif ":" in line:
            k, _, v = line.partition(":")
            current_key = k.strip().lower()
            headers[current_key] = v.strip()
    return headers
