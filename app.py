from flask import Flask, render_template, request, jsonify
from utils.email_parser import parse_email
from utils.header_analyzer import analyze_headers
from utils.url_analyzer import analyze_urls
from utils.risk_scorer import score_email
import os

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 5 * 1024 * 1024  # 5MB max upload


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/analyze", methods=["POST"])
def analyze():
    result = {}

    # --- Handle .eml file upload ---
    if "eml_file" in request.files and request.files["eml_file"].filename:
        file = request.files["eml_file"]
        raw = file.read().decode("utf-8", errors="replace")
        parsed = parse_email(raw=raw)
    else:
        # Manual field input
        parsed = parse_email(
            sender=request.form.get("sender", ""),
            subject=request.form.get("subject", ""),
            body=request.form.get("body", ""),
            raw_headers=request.form.get("raw_headers", ""),
            links=request.form.get("links", ""),
        )

    # --- Run analysis modules ---
    header_report = analyze_headers(parsed)
    url_report = analyze_urls(parsed["urls"])
    score_report = score_email(parsed, header_report, url_report)

    result = {
        "parsed": parsed,
        "headers": header_report,
        "urls": url_report,
        "score": score_report,
    }

    return jsonify(result)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
