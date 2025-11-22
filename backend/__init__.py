"""
Initialize the phishing_email_analyzer package.
Exposes the Flask-RESTX namespace and loads extensions.
"""

# Public namespace export
from .route import mail_ns

# Auto-register extension endpoints
from . import extension as _extension

__all__ = ["mail_ns"]
