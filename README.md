EGuard – Email Phishing Analysis and Detection
Advanced Multi-Phase Email Security Analysis Tool
📌 Overview

EGuard is an AI-assisted phishing detection framework designed to analyze email messages, identify social-engineering patterns, detect spoofing attempts, and classify risk levels.
The system focuses on parsing uploaded .eml files, extracting headers, links, attachments, and applying heuristic and structural checks.

The project is built collaboratively by:

Backend Team – Responsible for the full analysis pipeline and API endpoints

Frontend Team – Builds the UI that displays results and dashboards

Email Simulation Team – Crafts realistic phishing emails to test detections

The analyzer returns a detailed report including:

Risk verdict: safe, suspicious, malicious

Authentication results (SPF/DKIM/DMARC)

Link and attachment risk indicators

Extra social-engineering flags

Raw structured JSON (optional)

📁 Repository Structure
phishing_email_analyzer/
│
├── calc_score.py        # Phase 4: scoring system and risk verdicts
├── detection.py         # Phase 3: detection rules and heuristics
├── extraction.py        # Phase 1: raw email extraction
├── parsing.py           # Phase 2: header/body parsing
├── orchestration.py     # Full pipeline orchestrator
├── services.py          # API-facing service layer
├── route.py             # REST API endpoints for scanning
├── extension.py         # External scan support (/ext-scan endpoint)
└── __init__.py          # Package initializer


Each file represents a logical stage of the phishing-email analysis workflow.

🚀 Features
✔ Full Email Parsing

Parses raw .eml files including multipart MIME parts

Extracts text, HTML, attachments, URLs, IPs, email addresses

✔ Heuristic Detection Engine

Detects:

Suspicious redirects

Typosquatting domains

Brand impersonation

Social-engineering wording

Header inconsistencies (From vs Return-Path vs Reply-To)

SPF/DKIM/DMARC failures

Risky or double-extension attachments

Clickable images & HTML forms

✔ Weighted Risk Scoring

Computes a normalized 0–100 score

Assigns verdict: safe / suspicious / high-risk / malicious

✔ REST API Support

Two main endpoints:

POST /tools/Phishing-email/text-scan

POST /tools/Phishing-email/eml-scan

✔ Frontend-Friendly Output

Compact, standardized JSON

Optionally includes the full raw report

🧠 How the Analysis Pipeline Works

The system follows a strict multi-phase approach:

1. Extraction Phase

📌 Implemented in: extraction.py

Converts any payload to bytes

Reads .eml message structure

Extracts raw headers, body parts, attachments

Collects all URLs, emails, IPs

Example output:

{
  "text_parts": ["Please reset your password."],
  "raw_links": ["https://attacker.com/reset"],
  "attachments": [{ "filename": "invoice.pdf", "content_type": "application/pdf" }]
}

2. Parsing Phase

📌 Implemented in: parsing.py

Extracts structured objects:

Sender domains

SPF/DKIM/DMARC fields

Normalized links (href, absolute URL, text-domain)

Attachment metadata

Example output:

{
  "headers": { "from_domain": "attacker.com" },
  "body": { "links": [ { "absolute_domain": "attacker.com" } ] },
  "auth": { "spf": "fail", "dkim": "fail" }
}

3. Detection Phase

📌 Implemented in: detection.py

Applies multiple heuristics:

detect_suspicious_links

detect_header_forgery

detect_display_name_spoofing

detect_typosquatting

detect_html_forms

detect_clickable_images

detect_social_engineering_language

…and more

Example:

{
  "suspicious_links": [{ "reason": "domain_not_allowed" }],
  "header_issues": ["header_domain_mismatch"],
  "extra_flags": {
    "anchor_redirect": [...],
    "typosquatting": [...]
  }
}

4. Scoring Phase

📌 Implemented in: calc_score.py

Counts number of hits per category

Multiplies by predefined weights

Normalizes score into 0–100

Selects verdict

Example:

{
  "score": 92.5,
  "verdict": "malicious"
}

5. Orchestration Phase

📌 Implemented in: orchestration.py

Connects all phases:

Extraction → Parsing → Detection → Scoring


Returns final structured report.

6. Services + API Layer

📌 Implemented in:

services.py

route.py

extension.py

Exposes REST endpoints:

POST /tools/Phishing-email/eml-scan

Upload .eml via multipart/form-data.

POST /tools/Phishing-email/text-scan

Send raw email content as text.

📡 API Examples
Scan EML File

Request

curl -X POST \
  -H "Authorization: Bearer <token>" \
  -F "eml=@email.eml" \
  https://yourserver/tools/Phishing-email/eml-scan


Response

{
  "sender": "support@attacker.com",
  "subject": "Urgent!",
  "status": "malicious",
  "score": 92.5,
  "links": 3,
  "attachments": 1,
  "findings": {...},
  "raw_report": {...}
}

🧪 Testing – Email Simulation Guide

The Email Simulation Team must prepare three .eml test emails:

1. Malicious Email

Should include:

Spoofed sender name

Mismatched From/Return-Path

SPF/DKIM/DMARC failures

Typosquatted domains (paypa1.com)

Double-extension attachments (invoice.pdf.exe)

Urgent language

Fake login HTML form

Clickable image links

Expected verdict: malicious

2. Suspicious Email

Should include:

One mismatched link

Slightly coercive wording

No dangerous attachment

Expected verdict: suspicious

3. Safe Email

Should include:

Real matching headers

SPF/DKIM/DMARC pass

No suspicious links

No attachments or safe attachments

Expected verdict: safe

🛠️ Running the Backend
Requirements

Python 3.10+

Flask / Flask-RESTX

JWT module

BeautifulSoup4

Install dependencies:

pip install -r requirements.txt


Run the API server:

python main.py

🖥️ Frontend Integration

The frontend should:

✔ Allow users to upload .eml files
✔ Call the /eml-scan endpoint
✔ Display:

Sender

Subject

Verdict and Score

Suspicious links

Header issues

Risky attachments

Extra flags
✔ Provide raw JSON viewer
✔ Store scan history locally

🤝 Contributing

Fork the repository

Create a feature branch

Follow PEP-8 style

Add unit tests for new detectors

Submit a pull request

📄 License

This project is part of the academic work:
EGuard – Email Phishing Analysis and Detection
