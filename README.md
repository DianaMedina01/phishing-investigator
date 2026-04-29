# PhishInvestigator — Email Forensics & Phishing Detection

A Flask web app that analyzes suspicious emails and produces a forensic report.

## Project Structure

```
phishing-investigator/
├── app.py                    # Flask entry point
├── requirements.txt
├── utils/
│   ├── email_parser.py       # Parses .eml files or manual input
│   ├── header_analyzer.py    # SPF/DKIM/DMARC, spoofing, routing checks
│   ├── url_analyzer.py       # URL heuristics + PhishTank API
│   └── risk_scorer.py        # Combines signals into final verdict
├── templates/
│   └── index.html
└── static/
    ├── css/style.css
    └── js/main.js
```

## Setup

### 1. Install dependencies
```bash
cd phishing-investigator
pip install -r requirements.txt
```

### 2. (Optional) Add your PhishTank API key
Get a free key at https://www.phishtank.com/api_register.php

```bash
# Mac/Linux
export PHISHTANK_API_KEY="your_key_here"

# Windows
set PHISHTANK_API_KEY=your_key_here
```

Without this key, the app still works — URL analysis runs on heuristics only.

### 3. Run the app
```bash
python app.py
```

Then open http://localhost:5000 in your browser.

## Features

- **Manual input**: Paste sender, subject, body, and links
- **.eml upload**: Drag-and-drop or upload a raw email file
- **Header paste**: Paste raw email headers for SPF/DKIM/DMARC analysis
- **URL analysis**: Heuristic checks + optional PhishTank API lookup
- **Risk scoring**: Weighted combination of all signals → 0–100 score
- **Verdict**: PHISHING / SUSPICIOUS / LIKELY SAFE

## Detection Signals

| Signal | Source |
|--------|--------|
| SPF / DKIM / DMARC fail | Email headers |
| Domain typosquatting | Sender field |
| Reply-To mismatch | Email headers |
| Suspicious TLDs (.ru, .tk, .xyz...) | Sender / URLs |
| Urgency language | Subject / Body |
| Credential harvesting phrases | Body |
| Brand impersonation | Body + sender mismatch |
| URL shorteners | URLs |
| IP-based URLs | URLs |
| Subdomain brand abuse | URLs |
| PhishTank database match | URLs (requires API key) |

## Getting Your PhishTank API Key

1. Go to https://www.phishtank.com/api_register.php
2. Create a free account
3. Register for an API key
4. Set the `PHISHTANK_API_KEY` environment variable as shown above
