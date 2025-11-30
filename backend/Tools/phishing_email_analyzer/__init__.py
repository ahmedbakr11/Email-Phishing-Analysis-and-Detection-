from .route import mail_ns  # defines the namespace
from . import extension as _extension  # registers /ext-scan on mail_ns

__all__ = ["mail_ns"]
