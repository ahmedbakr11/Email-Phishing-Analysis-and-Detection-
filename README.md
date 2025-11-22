## 📌 Overview
EGuard is a multi-stage phishing-email analysis framework that processes `.eml` files, extracts and parses email content, evaluates heuristic indicators, computes a weighted risk score (0–100), and produces a structured JSON report. The system identifies a wide spectrum of malicious behaviors, including:

- Spoofed sender identities  
- Malicious redirects  
- Typosquatted domains  
- Fake login pages  
- Dangerous or deceptive attachments  
- Social-engineering language  
- Forged SPF / DKIM / DMARC headers  
- Brand impersonation  

This work is part of the academic cybersecurity project **“EGuard – Email Phishing Analysis and Detection.”**

---

## 📁 Repository Structure


phishing_email_analyzer/
│
├── calc_score.py        # Phase 4: scoring system and risk verdicts
├── detection.py         # Phase 3: heuristic detection rules
├── extraction.py        # Phase 1: raw email extraction
├── parsing.py           # Phase 2: header, body, and link parsing
├── orchestration.py     # Full analysis pipeline coordinator
├── services.py          # API service layer for scan endpoints
├── route.py             # REST API endpoints
├── extension.py         # Additional external scan endpoints
└── init.py          # Package initializer

---

## 🧠 System Architecture

EGuard operates through a structured four-phase pipeline:

1. **Extraction**
2. **Parsing**
3. **Detection**
4. **Scoring**

The **orchestration** layer connects each phase and generates the final JSON report.

---

## 🔍 Phase Details

### **PHASE 1 — Extraction**  
**File:** `extraction.py`

Responsibilities:
- Parse `.eml` MIME structure  
- Extract HTML, plain text, and attachments  
- Collect URLs, email addresses, and IP addresses  

---

### **PHASE 2 — Parsing**  
**File:** `parsing.py`

Responsibilities:
- Extract domains from sender-related headers  
- Parse SPF, DKIM, and DMARC authentication results  
- Normalize and analyze HTML links  
- Compute SHA-256 hashes for attachments  

---

### **PHASE 3 — Detection**  
**File:** `detection.py`

Responsibilities:
- Detect mismatching or suspicious redirects  
- Identify header domain inconsistencies  
- Flag SPF/DKIM/DMARC failures  
- Identify dangerous attachment types  
- Detect double-extension tricks (e.g., `invoice.pdf.exe`)  
- Analyze for social-engineering language  
- Detect clickable images, HTML forms, brand impersonation  
- Detect typosquatted or homograph domains  

---

### **PHASE 4 — Scoring**  
**File:** `calc_score.py`

Responsibilities:
- Count triggered detectors  
- Apply weighted scoring logic  
- Normalize output to 0–100  
- Assign risk verdicts:  
  - `safe`  
  - `suspicious`  
  - `high-risk`  
  - `malicious`  

---

## 🔗 Pipeline Orchestration  
**File:** `orchestration.py`

Use:
```python
report = analyze_phishing_email(source)

The final report includes:


Extraction results


Parsed email components


Detection flags


Scoring summary



🌐 API Layer
Implemented in:


route.py


services.py


extension.py


REST Endpoints
MethodEndpointDescriptionPOST/tools/Phishing-email/text-scanScan raw email textPOST/tools/Phishing-email/eml-scanUpload and scan .eml filePOST/tools/Phishing-email/ext-scanExternal scan (Gmail/Outlook)

📡 Example API Usage
1. Upload and Scan a .eml File
curl -X POST \
  -H "Authorization: Bearer <token>" \
  -F "eml=@example.eml" \
  https://your-api/tools/Phishing-email/eml-scan

2. Example JSON Response
{
  "sender": "support@attacker.com",
  "subject": "Urgent Account Verification",
  "status": "malicious",
  "score": 92.5,
  "links": 3,
  "attachments": 1,
  "findings": {
    "suspicious_links": [...],
    "header_issues": [...],
    "risky_attachments": [...],
    "extra_flags": {...}
  },
  "raw_report": {...}
}


🧪 Testing Requirements (Email Simulation Team)
Prepare three .eml files to verify full detector coverage.
1. Malicious Email
Include:


Spoofed branding (e.g., “PayPal Security”)


Header inconsistencies (From ≠ Return-Path)


SPF/DKIM/DMARC failures


Typosquatted domain (paypa1.com)


Dangerous attachment (invoice.pdf.exe)


HTML login form


Clickable image redirect


Urgent or coercive language


Expected: malicious

2. Suspicious Email
Include:


One suspicious redirect


Mild coercive text


No harmful attachments


Expected: suspicious

3. Safe Email
Include:


Matching headers


Clean authentication results


No suspicious links or language


No risky attachments


Expected: safe

🖥️ Frontend Responsibilities
The frontend should:


Support .eml upload via drag-and-drop or file picker


Use the /eml-scan endpoint


Display:


Risk score


Verdict


Sender information


Suspicious links


Header issues


Risky attachments


Additional flags


Expandable raw JSON




Store recent scan history locally



🛠️ Running the Backend Locally
1. Install Dependencies
pip install -r requirements.txt

2. Start the Server
python main.py


🤝 Contributing
To contribute:


Fork the repository


Create a feature branch


Commit changes


Follow PEP-8 standards


Submit a pull request



📄 License
This project is part of the academic cybersecurity work:
“EGuard – Email Phishing Analysis and Detection”
