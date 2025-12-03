from flask import Flask
from flask_cors import CORS
from flask_jwt_extended import JWTManager

from .extensions import db, migrate


def create_app(Config):
    app = Flask(__name__)
    app.config.from_object(Config)
    CORS(app)  # allow front-end running on a different port to communicate with backend
    JWTManager(app)

    db.init_app(app)  # Database initiation
    migrate.init_app(app, db)  # Migration initiation

    return app
