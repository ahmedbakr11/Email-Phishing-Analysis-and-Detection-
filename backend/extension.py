from flask import request
from flask_restx import Resource, fields
from flask_jwt_extended import jwt_required

from .route import mail_ns
from .services import mail_to_bytes, text_scan


#########################
######### GMAIL #########
#########################
ExtInput = mail_ns.model(
    "ExtInput",
    {
        "provider": fields.String(required=True, description="Email Provider Gmail/Outlook"),
        "gmail_message_id": fields.String(required=True, description="Email message ID"),
        "body": fields.String(required=True, description="Raw email content to scan"),
    },
)

ExtOutput = mail_ns.model(
    "ExtOutput",
    {
        "sender": fields.String(description="the senders email"),
        "subject": fields.String(description="Mail subject"),
        "verdict": fields.String(description="Mapped verdict (safe | suspicious | malicious)"),
        "status": fields.String(required=True, description="safe | suspicious | malicious"),
        "score": fields.Float(required=True, description="Risk score"),
        "attachments": fields.Integer(description="number of attachments in mail"),
        "links": fields.Integer(description="number of links in mail"),
        "findings": fields.Raw(description="detailed findings"),
        "cached": fields.Boolean(description="Was it cached?"),
    },
)

@mail_ns.route("/ext-scan")
class ExtScan(Resource):
    @jwt_required()
    def post(self):

        raw_payload = None
        provider = None
        gmail_message_id = None

        if request.is_json:
            data = request.get_json()
            provider = data.get("provider")
            gmail_message_id = data.get("gmail_message_id")
            body_content = data.get("body")

            if not provider or not gmail_message_id:
                return {"error": "bad input", "detail": "'provider' and 'gmail_message_id' are required"}, 400
            if not body_content:
                return {"error": "bad input", "detail": "'body' is required for scanning"}, 400
            raw_payload = mail_to_bytes(body_content)
        else:
            body = request.get_data()
            if not body:
                return {"error": "bad input", "detail": "request body is empty"}, 400
            raw_payload = mail_to_bytes(body)

        payload = text_scan(raw_payload)
        status_code = payload.pop("http_status", 200)
        if status_code < 400:
            payload["cached"] = False

        return payload, status_code
