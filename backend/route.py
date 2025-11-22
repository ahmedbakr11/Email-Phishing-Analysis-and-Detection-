"""
API endpoints for Phishing Email Analyzer.
Provides: 
    - /text-scan  (scan raw text)
    - /eml-scan   (scan uploaded .eml files)
"""

from flask import request
from flask_restx import Namespace, Resource, fields
from flask_jwt_extended import jwt_required

from .services import eml_scan, text_scan


# ---------------------------------------------------------
# 1. NAMESPACE
# ---------------------------------------------------------

mail_ns = Namespace(
    "tools/Phishing-email",
    description="Namespace for phishing email endpoint"
)


# ---------------------------------------------------------
# 2. REQUEST & RESPONSE MODELS
# ---------------------------------------------------------

EmailInput = mail_ns.model(
    "EmailInput",
    {
        "body": fields.String(
            required=True,
            description="Content of the email body to scan"
        ),
    },
)

Email_scan_output = mail_ns.model(
    "Email_scan_output",
    {
        "sender": fields.String(description="Sender email"),
        "subject": fields.String(description="Mail subject"),
        "verdict": fields.String(description="Mapped verdict: safe | suspicious | malicious"),
        "status": fields.String(required=True, description="safe | suspicious | malicious"),
        "score": fields.Float(description="Risk score 0–100"),
        "attachments": fields.Integer(description="Number of attachments"),
        "links": fields.Integer(description="Number of links"),
        "findings": fields.Raw(description="Detailed detection results"),
        "raw_report": fields.Raw(description="Full report (for EML scans only)"),
    },
)

Email_error_model = mail_ns.model(
    "Email_error_model",
    {
        "error": fields.String(required=True),
        "detail": fields.String(),
    },
)


# ---------------------------------------------------------
# 3. ROUTE: TEXT-BASED SCAN
# ---------------------------------------------------------

@mail_ns.route("/text-scan")
class FullScan(Resource):

    @mail_ns.response(400, "Bad request", Email_error_model)
    @jwt_required()
    def post(self):
        """Scan plain text email content."""
        if request.is_json:
            data = request.get_json()
            body = data.get("body")

            if not body:
                return {"error": "bad input", "detail": "'body' is required in JSON"}, 400

            raw_bytes = body.encode("utf-8")
            payload = text_scan(raw_bytes)
            status_code = payload.pop("http_status", 200)
            return payload, status_code

        return {
            "error": "unsupported content type",
            "detail": "send JSON with 'body'"
        }, 400


# ---------------------------------------------------------
# 4. ROUTE: EML FILE UPLOAD SCAN
# ---------------------------------------------------------

@mail_ns.route("/eml-scan")
class UploadScan(Resource):

    @mail_ns.response(400, "Bad request", Email_error_model)
    @jwt_required()
    def post(self):
        """Upload and scan an .eml file."""
        ctype = request.content_type or ""
        if not ctype.startswith("multipart/form-data"):
            return {
                "error": "unsupported content type",
                "detail": "send multipart/form-data with an 'eml' file",
            }, 400

        eml_file = request.files.get("eml")
        if not eml_file:
            return {"error": "bad input", "detail": "file field 'eml' is missing"}, 400

        eml_bytes = eml_file.read()
        if not eml_bytes:
            return {"error": "bad input", "detail": "uploaded file is empty"}, 400

        response_to_frontend = eml_scan(eml_bytes)
        status_code = response_to_frontend.pop("http_status", 200)
        return response_to_frontend, status_code
