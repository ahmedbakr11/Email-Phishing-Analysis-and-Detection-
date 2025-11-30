from flask import Flask
from flask_cors import CORS
from flask_jwt_extended import JWTManager, get_jwt, verify_jwt_in_request
from flask_restx import abort

from .extensions import db, migrate


## Flask app creation
def create_app(Config):

    app = Flask(__name__)
    app.config.from_object(Config)
    CORS(app)  ##allow front-end running on a diffrent port communicate with backend
    JWTManager(app)

    db.init_app(app)  ## Database intiation
    migrate.init_app(app, db)  ## Migration intiation

    return app

# func to verify token for admin or normal user 
# This func get at any route that u want to protect
def require_admin():
    verify_jwt_in_request(optional=False)
    claims = get_jwt()
    if claims.get("role") != "admin":
        abort(403, error="Admin access required")