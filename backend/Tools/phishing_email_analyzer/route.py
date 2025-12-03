from flask import request
from flask_restx import Namespace, Resource, fields
from flask_jwt_extended import jwt_required

from .services import eml_scan, text_scan



mail_ns = Namespace("tools/Phishing-email", description="namespace for phisihing email endpoint")

EmailInput = mail_ns.model(
    "EmailInput",
    {
        "body": fields.String(required=True, description="the content of the email body"),
    },
)

Email_scan_output = mail_ns.model(
    "Email_scan_output",
    {
        "sender": fields.String(description="the senders email"),
        "subject": fields.String(description="Mail subject"),
        "verdict": fields.String(description="Mapped verdict (safe | suspicious | malicious)"),
        "status": fields.String(required=True, description="safe | suspicious | malicious"),
        "score": fields.Float(description="risk score 0-100"),
        "attachments": fields.Integer(description="number of attachments in mail"),
        "links": fields.Integer(description="number of links in mail"),
        "findings": fields.Raw(description="detailed findings"),
        "raw_report": fields.Raw(description="full analysis report (upload only)"),
    },
)

Email_error_model = mail_ns.model(
    "Email_error_model",
    {
        "error": fields.String(required=True),
        "detail": fields.String(),
    },
)

@mail_ns.route("/text-scan")
class FullScan(Resource):

    @mail_ns.response(400, "Bad request", Email_error_model)
    @jwt_required()
    def post(self):
        # --- Case 2: JSON containing body text ---
        if request.is_json:
            data = request.get_json()
            body = data.get("body")
            if not body:
                return {"error": "bad input", "detail": "'body' is required in JSON"}, 400
            raw_bytes = body.encode("utf-8")
            payload = text_scan(raw_bytes)
            status_code = payload.pop("http_status", 200)
            return payload, status_code

        # --- Invalid content type ---
        return {
            "error": "unsupported content type",
            "detail": "send JSON with 'body'"
        }, 400


@mail_ns.route("/eml-scan")
class UploadScan(Resource):
    @mail_ns.response(400, "Bad request", Email_error_model)
    @jwt_required()
    def post(self):
        """Uploads an EML file, runs the phishing analyzer, and returns a concise report."""
        if not request.content_type or not request.content_type.startswith("multipart/form-data"):
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

