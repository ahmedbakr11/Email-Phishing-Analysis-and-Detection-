from flask import Flask
from flask_restx import Api

from .extensions import db
from . import create_app
from .models import User
from .auth import auth_ns
from ..config import devconfig
from ..Tools.phishing_email_analyzer.route import mail_ns


app = create_app(devconfig)

# /docs is the default documentation for the api, to access the api route to /api/..
api = Api(app, doc="/docs", prefix="/api")

api.add_namespace(auth_ns)
api.add_namespace(mail_ns)





@app.shell_context_processor
def make_shell_context():
    return {"db": db, "User": User}


if __name__ == "__main__":
    app.run(host="0.0.0.0", debug=True, port=5000)
